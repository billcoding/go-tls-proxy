package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	DefaultSocket = "unix:///var/run/docker.sock"
	CacheTTL      = 2 * time.Second
)

type Resolver struct {
	baseURL  string
	client   *http.Client
	ttl      time.Duration
	mu       sync.Mutex
	cache    map[string]cacheEntry
	epoch    map[string]uint64
	inflight map[string]*flight
}

type cacheEntry struct {
	addr    string
	expires time.Time
}

// flight 合并同一容器上同时发生的查询，避免缓存刚过期时每条连接各打一遍 Docker。
type flight struct {
	done chan struct{}
	ip   string
	err  error
}

type dialTarget struct {
	unixPath string
	baseURL  string
}

type inspectBody struct {
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	NetworkSettings struct {
		Networks json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

type networkEndpoint struct {
	IPAddress         string `json:"IPAddress"`
	GlobalIPv6Address string `json:"GlobalIPv6Address"`
}

func NormalizeSocket(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultSocket, nil
	}
	if _, err := parseSocket(raw); err != nil {
		return "", err
	}
	return raw, nil
}

func parseSocket(raw string) (dialTarget, error) {
	if strings.HasPrefix(raw, "/") {
		return dialTarget{unixPath: raw, baseURL: "http://docker"}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return dialTarget{}, fmt.Errorf("docker.socket 无效: %s", raw)
	}
	switch u.Scheme {
	case "unix":
		if u.Path == "" {
			return dialTarget{}, fmt.Errorf("docker.socket 缺少套接字路径: %s", raw)
		}
		return dialTarget{unixPath: u.Path, baseURL: "http://docker"}, nil
	case "http", "https":
		if u.Host == "" {
			return dialTarget{}, fmt.Errorf("docker.socket 无效: %s", raw)
		}
		return dialTarget{baseURL: strings.TrimRight(raw, "/")}, nil
	default:
		return dialTarget{}, fmt.Errorf("docker.socket 只支持 unix://、http://、https:// 或绝对路径: %s", raw)
	}
}

func New(socket string) (*Resolver, error) {
	socket, err := NormalizeSocket(socket)
	if err != nil {
		return nil, err
	}
	target, err := parseSocket(socket)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if target.unixPath != "" {
		client = unixClient(target.unixPath)
	}
	return newResolver(target.baseURL, client), nil
}

func NewClient(baseURL string, client *http.Client) *Resolver {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return newResolver(baseURL, client)
}

func newResolver(baseURL string, client *http.Client) *Resolver {
	return &Resolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  client,
		ttl:     CacheTTL,
		cache:   map[string]cacheEntry{},
	}
}

func unixClient(path string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "unix", path)
			},
			DisableCompression:  true,
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// Resolve 把容器名解析成 ip:port。fresh 为 false 时，CacheTTL 内复用上次成功结果。
// 容器重启后 IP 会变，调用方应在每次转发或每条新连接上调用，而不是只在启动时解析一次。
// 短缓存过期后会重新查询。连不上解析出来的地址时，调用方应 Forget 后再用 fresh=true 查一次。
// 同一容器上重叠的查询会合成一次 Docker 请求。
func (r *Resolver) Resolve(ctx context.Context, container, port string, fresh bool) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := cacheKey(container, port)
	if !fresh {
		if addr, ok := r.cached(key); ok {
			return addr, nil
		}
	}
	epoch := r.epochOf(key)
	ip, err := r.lookupFlight(ctx, container)
	if err != nil {
		return "", err
	}
	addr := net.JoinHostPort(ip, port)
	r.store(key, addr, epoch)
	return addr, nil
}

// Forget 丢掉这个容器端口的地址缓存。连接失败时调用，避免继续把请求送到旧 IP。
func (r *Resolver) Forget(container, port string) {
	if r == nil {
		return
	}
	key := cacheKey(container, port)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, key)
	if r.epoch == nil {
		r.epoch = map[string]uint64{}
	}
	r.epoch[key]++
}

func cacheKey(container, port string) string {
	return container + "\x00" + port
}

func (r *Resolver) cached(key string) (string, bool) {
	if r.ttl <= 0 {
		return "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ent, ok := r.cache[key]
	if !ok || !time.Now().Before(ent.expires) {
		return "", false
	}
	return ent.addr, true
}

func (r *Resolver) epochOf(key string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.epoch[key]
}

func (r *Resolver) store(key, addr string, epoch uint64) {
	if r.ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch[key] != epoch {
		return
	}
	if r.cache == nil {
		r.cache = map[string]cacheEntry{}
	}
	r.cache[key] = cacheEntry{addr: addr, expires: time.Now().Add(r.ttl)}
}

func (r *Resolver) lookupFlight(ctx context.Context, container string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.mu.Lock()
	if r.inflight == nil {
		r.inflight = map[string]*flight{}
	}
	if existing, ok := r.inflight[container]; ok {
		r.mu.Unlock()
		select {
		case <-existing.done:
			return existing.ip, existing.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	r.inflight[container] = f
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		if r.inflight[container] == f {
			delete(r.inflight, container)
		}
		r.mu.Unlock()
		close(f.done)
	}()

	f.ip, f.err = r.lookup(ctx, container)
	return f.ip, f.err
}

func (r *Resolver) lookup(ctx context.Context, container string) (string, error) {
	endpoint := r.baseURL + "/containers/" + url.PathEscape(container) + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("连接 Docker 失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("读取容器 %s 的信息失败: %w", container, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("找不到容器 %s", container)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("查询容器 %s 失败: %s", container, resp.Status)
	}
	var info inspectBody
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("解析容器 %s 的信息失败: %w", container, err)
	}
	if !info.State.Running {
		return "", fmt.Errorf("容器 %s 未运行", container)
	}
	return r.pickIP(container, info.NetworkSettings.Networks)
}

// pickIP 按 Docker 返回的网络顺序，取第一个有 IPv4 或 IPv6 地址的网络。
func (r *Resolver) pickIP(container string, raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", fmt.Errorf("容器 %s 没有可用的网络 IP", container)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("解析容器 %s 的网络信息失败: %w", container, err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return "", fmt.Errorf("解析容器 %s 的网络信息失败", container)
	}
	for dec.More() {
		if _, err := dec.Token(); err != nil {
			return "", fmt.Errorf("解析容器 %s 的网络信息失败: %w", container, err)
		}
		var ep networkEndpoint
		if err := dec.Decode(&ep); err != nil {
			return "", fmt.Errorf("解析容器 %s 的网络信息失败: %w", container, err)
		}
		ip := strings.TrimSpace(ep.IPAddress)
		if ip == "" {
			ip = strings.TrimSpace(ep.GlobalIPv6Address)
		}
		if ip != "" {
			return ip, nil
		}
	}
	return "", fmt.Errorf("容器 %s 没有可用的网络 IP", container)
}
