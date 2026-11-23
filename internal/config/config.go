package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/billcoding/go-tls-proxy/internal/docker"
	"gopkg.in/yaml.v3"
)

const (
	ChallengeTLSALPN = "tls-alpn-01"
	ChallengeHTTP    = "http-01"
	ModeHTTP         = "http"
	ModeTCP          = "tcp"
)

type File struct {
	Certificate Certificate `yaml:"certificate"`
	Docker      Docker      `yaml:"docker"`
	Proxies     []Proxy     `yaml:"proxies"`
}

type Docker struct {
	Socket string `yaml:"socket"`
}

// Certificate 里只有 RenewEvery 和 StorageDir 来自 YAML。
// 其余字段在 normalize 里写死；旧配置里的 provider、email、ips、staging、challenge、http_port 等会被忽略。
type Certificate struct {
	RenewEvery string `yaml:"renew_every"`
	StorageDir string `yaml:"storage_dir"`

	Email         string        `yaml:"-"`
	IPs           []string      `yaml:"-"`
	Staging       bool          `yaml:"-"`
	Directory     string        `yaml:"-"`
	Challenge     string        `yaml:"-"`
	HTTPPort      int           `yaml:"-"`
	Profile       string        `yaml:"-"`
	RenewInterval time.Duration `yaml:"-"`
}

type Proxy struct {
	// Name 是代理名字。redirect 可以写这个名字，让客户端跳到这里。
	Name string `yaml:"name"`
	// Listen 是监听地址，例如 :443。
	Listen string `yaml:"listen"`
	// Mode 是 http 或 tcp。省略时是 http。
	Mode string `yaml:"mode"`
	// Backend 是唯一后端，和 routes 二选一。
	Backend string `yaml:"backend"`
	// Routes 按路径转发或跳转。
	Routes []Route `yaml:"routes"`
	// InsecureSkipVerify 为 true 时不校验后端 HTTPS 证书。
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// TLS 只对 http 模式有意义。省略或 true 仍是 HTTPS；false 才明文监听。
	// TCP 模式忽略它，始终做 TLS。
	// 同一监听地址可以同时有一条明文和一条 HTTPS 的 http 代理。
	TLS *bool `yaml:"tls"`
}

type Route struct {
	// Path 是路径前缀，必须以 / 开头。
	Path string `yaml:"path"`
	// Backend 是这条路径的后端，与 redirect 互斥。
	Backend string `yaml:"backend"`
	// Redirect 是跳转目标：带主机的 http 或 https 地址，或另一个 http 代理的 name。
	Redirect string `yaml:"redirect"`
	// RedirectCode 只允许 301（永久）或 302（临时）。省略时是 302。
	RedirectCode int `yaml:"redirect_code"`
	// RedirectTo 在 redirect 写成代理名时记下目标协议和端口。主机等请求到来再填。
	RedirectTo *NamedRedirect `yaml:"-"`
}

// NamedRedirect 是按代理名跳转时的协议和端口。
type NamedRedirect struct {
	Scheme string
	Port   string
}

// PlainHTTP 表示这个代理按明文 HTTP 监听，不做 TLS。
// 只有 mode 为 http 且写了 tls: false 才成立。省略或 tls: true 仍是 HTTPS。
// TCP 模式即使写了 tls: false 也返回 false。
func (p Proxy) PlainHTTP() bool {
	return p.Mode == ModeHTTP && p.TLS != nil && !*p.TLS
}

// UnmarshalYAML 只读取仍生效的字段。已删除的键留在旧配置里时直接跳过，避免已部署的机器无法启动。
func (c *Certificate) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("certificate 必须是一组配置")
	}
	var raw struct {
		RenewEvery string `yaml:"renew_every"`
		StorageDir string `yaml:"storage_dir"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	c.RenewEvery = raw.RenewEvery
	c.StorageDir = raw.StorageDir
	return nil
}

func (d *Docker) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("docker 必须是一组配置")
	}
	var raw struct {
		Socket string `yaml:"socket"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	d.Socket = raw.Socket
	return nil
}

func Load(path string) (*File, error) {
	return load(path)
}

func load(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("找不到配置文件 %s，可参考 config/config.example.yml", path)
		}
		return nil, fmt.Errorf("打开配置文件: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg File
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件: %w", err)
	}
	if err := cfg.normalize(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *File) normalize(baseDir string) error {
	socket, err := docker.NormalizeSocket(c.Docker.Socket)
	if err != nil {
		return err
	}
	c.Docker.Socket = socket

	cert := &c.Certificate
	cert.Email = ""
	cert.IPs = []string{"auto"}
	cert.Staging = false
	cert.Challenge = ChallengeHTTP
	cert.HTTPPort = 80
	cert.Profile = "shortlived"

	every, err := parseRenewEvery(cert.RenewEvery)
	if err != nil {
		return err
	}
	cert.RenewInterval = every

	if cert.StorageDir == "" {
		cert.StorageDir = "data"
	}
	if !filepath.IsAbs(cert.StorageDir) {
		cert.StorageDir = filepath.Join(baseDir, cert.StorageDir)
	}
	if dir := strings.TrimSpace(os.Getenv("GO_TLS_PROXY_ACME_DIRECTORY")); dir != "" {
		cert.Directory = dir
	}

	if len(c.Proxies) == 0 {
		return fmt.Errorf("proxies 至少要有一项")
	}

	names := map[string]struct{}{}
	used := map[string][]*listenOwner{}
	for i := range c.Proxies {
		p := &c.Proxies[i]
		if err := p.normalize(); err != nil {
			return err
		}
		if _, ok := names[p.Name]; ok {
			return fmt.Errorf("代理名字重复: %s", p.Name)
		}
		names[p.Name] = struct{}{}

		host, port, err := splitListen(p.Listen)
		if err != nil {
			return fmt.Errorf("代理 %s: %w", p.Name, err)
		}
		if port == strconv.Itoa(cert.HTTPPort) {
			return fmt.Errorf("代理 %s 占用了 %d 端口，该端口要留给 http-01 证书校验", p.Name, cert.HTTPPort)
		}
		me := &listenOwner{proxy: p, host: host}
		var partner *listenOwner
		for _, prev := range used[port] {
			if !hostsOverlap(prev.host, host) {
				continue
			}
			// 同一端口只允许恰好一条明文和一条 HTTPS 的 http 代理。
			if partner != nil || prev.paired || !ShareListen(*prev.proxy, *p) {
				return fmt.Errorf("监听地址冲突: %s 与 %s 都使用端口 %s", prev.proxy.Name, p.Name, port)
			}
			partner = prev
		}
		if partner != nil {
			partner.paired = true
			me.paired = true
		}
		used[port] = append(used[port], me)
	}
	if err := c.resolveNamedRedirects(); err != nil {
		return err
	}
	return nil
}

type listenOwner struct {
	proxy  *Proxy
	host   string
	paired bool
}

func hostsOverlap(a, b string) bool {
	return a == "*" || b == "*" || a == b
}

// ShareListen 判断两个 http 代理能否共用一个监听套接字。
// 主机和端口相同，且恰好一个是明文，另一个是 HTTPS。
func ShareListen(a, b Proxy) bool {
	if a.Mode != ModeHTTP || b.Mode != ModeHTTP {
		return false
	}
	if a.PlainHTTP() == b.PlainHTTP() {
		return false
	}
	ah, ap, aerr := splitListen(a.Listen)
	bh, bp, berr := splitListen(b.Listen)
	if aerr != nil || berr != nil {
		return false
	}
	return ah == bh && ap == bp
}

func (p *Proxy) normalize() error {
	p.Listen = strings.TrimSpace(p.Listen)
	if p.Listen == "" {
		return fmt.Errorf("代理缺少 listen")
	}
	if p.Name == "" {
		p.Name = p.Listen
	}
	switch p.Mode {
	case "":
		p.Mode = ModeHTTP
	case ModeHTTP, ModeTCP:
	default:
		return fmt.Errorf("代理 %s 的 mode 只能是 http 或 tcp", p.Name)
	}

	switch p.Mode {
	case ModeTCP:
		if len(p.Routes) > 0 {
			return fmt.Errorf("代理 %s 是 tcp 模式，不能再写 routes", p.Name)
		}
		backend, err := NormalizeTCP(p.Backend)
		if err != nil {
			return fmt.Errorf("代理 %s: %w", p.Name, err)
		}
		p.Backend = backend
	case ModeHTTP:
		if p.Backend != "" && len(p.Routes) > 0 {
			return fmt.Errorf("代理 %s 请只写 backend 或 routes 其中一种", p.Name)
		}
		if len(p.Routes) == 0 {
			if strings.TrimSpace(p.Backend) == "" {
				return fmt.Errorf("代理 %s 需要 backend 或 routes", p.Name)
			}
			p.Routes = []Route{{Path: "/", Backend: p.Backend}}
			p.Backend = ""
		}
		seen := map[string]struct{}{}
		for i := range p.Routes {
			path, err := NormalizePath(p.Routes[i].Path)
			if err != nil {
				return fmt.Errorf("代理 %s: %w", p.Name, err)
			}
			if _, ok := seen[path]; ok {
				return fmt.Errorf("代理 %s 的路径 %s 重复", p.Name, path)
			}
			seen[path] = struct{}{}
			p.Routes[i].Path = path
			if err := p.normalizeRoute(&p.Routes[i]); err != nil {
				return fmt.Errorf("代理 %s 的路径 %s: %w", p.Name, path, err)
			}
		}
	}
	return nil
}

// RealEmail 判断配置里是不是用户明确写的邮箱。
// 空字符串和 @example.com 会改由程序生成随机邮箱。
func RealEmail(email string) bool {
	email = strings.TrimSpace(email)
	return strings.Contains(email, "@") && !strings.HasSuffix(strings.ToLower(email), "@example.com")
}

func parseRenewEvery(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 72 * time.Hour, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok && !strings.Contains(days, "h") {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("certificate.renew_every 无效: %s", s)
		}
		s = strconv.Itoa(n*24) + "h"
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("certificate.renew_every 无效: %s", s)
	}
	if d < time.Hour {
		return 0, fmt.Errorf("certificate.renew_every 不能短于 1 小时")
	}
	return d, nil
}

func splitListen(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("监听地址 %s 需要写成 host:port，例如 :443", addr)
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("监听地址 %s 的端口无效", addr)
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "*"
	}
	return host, port, nil
}

func (p *Proxy) normalizeRoute(route *Route) error {
	backend := strings.TrimSpace(route.Backend)
	redirect := strings.TrimSpace(route.Redirect)
	if backend != "" && redirect != "" {
		return fmt.Errorf("不能同时写 backend 和 redirect")
	}
	if backend == "" && redirect == "" {
		if route.RedirectCode != 0 {
			return fmt.Errorf("写了 redirect_code 但没有 redirect")
		}
		return fmt.Errorf("需要 backend 或 redirect")
	}
	if backend != "" {
		if route.RedirectCode != 0 {
			return fmt.Errorf("写了 redirect_code 但没有 redirect")
		}
		normalized, err := NormalizeHTTPBackend(backend)
		if err != nil {
			return err
		}
		route.Backend = normalized
		route.Redirect = ""
		return nil
	}
	// 含 :// 或写成路径的，仍按绝对地址检查。其余留给后面按代理名解析。
	if strings.Contains(redirect, "://") || strings.HasPrefix(redirect, "/") {
		loc, code, err := NormalizeRedirect(redirect, route.RedirectCode)
		if err != nil {
			return err
		}
		route.Redirect = loc
		route.RedirectCode = code
		route.Backend = ""
		route.RedirectTo = nil
		return nil
	}
	code, err := normalizeRedirectCode(route.RedirectCode)
	if err != nil {
		return err
	}
	route.Redirect = redirect
	route.RedirectCode = code
	route.Backend = ""
	route.RedirectTo = nil
	return nil
}

func (c *File) resolveNamedRedirects() error {
	byName := make(map[string]*Proxy, len(c.Proxies))
	for i := range c.Proxies {
		byName[c.Proxies[i].Name] = &c.Proxies[i]
	}
	for i := range c.Proxies {
		p := &c.Proxies[i]
		for j := range p.Routes {
			route := &p.Routes[j]
			if route.Redirect == "" || absoluteRedirect(route.Redirect) {
				continue
			}
			target, ok := byName[route.Redirect]
			if !ok {
				return fmt.Errorf("代理 %s 的 redirect 找不到代理 %s", p.Name, route.Redirect)
			}
			if target.Name == p.Name {
				return fmt.Errorf("代理 %s 的 redirect 不能指向自己", p.Name)
			}
			if target.Mode != ModeHTTP {
				return fmt.Errorf("代理 %s 的 redirect 不能指向 tcp 模式的 %s", p.Name, target.Name)
			}
			_, port, err := splitListen(target.Listen)
			if err != nil {
				return fmt.Errorf("代理 %s: %w", target.Name, err)
			}
			scheme := "https"
			if target.PlainHTTP() {
				scheme = "http"
			}
			route.RedirectTo = &NamedRedirect{Scheme: scheme, Port: port}
		}
	}
	return nil
}

func absoluteRedirect(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.Opaque == ""
}

// NormalizeRedirect 检查重定向目标和状态码。
// 目标必须是带主机的 http 或 https 地址。状态码只允许 301 或 302，省略时用 302。
// 代理名不在这里解析。
func NormalizeRedirect(raw string, code int) (string, int, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || !absoluteRedirect(raw) {
		return "", 0, fmt.Errorf("redirect 需要写成完整的 http 或 https 地址: %s", raw)
	}
	code, err = normalizeRedirectCode(code)
	if err != nil {
		return "", 0, err
	}
	return u.String(), code, nil
}

func normalizeRedirectCode(code int) (int, error) {
	if code == 0 {
		code = 302
	}
	if code != 301 && code != 302 {
		return 0, fmt.Errorf("redirect_code 只能是 301 或 302")
	}
	return code, nil
}

func NormalizePath(path string) (string, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("路径必须以 / 开头: %s", path)
	}
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	return path, nil
}

func NormalizeHTTPBackend(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("后端地址为空")
	}
	if IsDockerBackend(raw) {
		return canonicalDocker(raw)
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	host := raw
	switch {
	case strings.HasPrefix(raw, "http://"):
		host = strings.TrimPrefix(raw, "http://")
	case strings.HasPrefix(raw, "https://"):
		host = strings.TrimPrefix(raw, "https://")
	default:
		return "", fmt.Errorf("后端协议只支持 http 或 https: %s", raw)
	}
	host = strings.TrimSuffix(host, "/")
	if _, _, err := net.SplitHostPort(host); err != nil {
		return "", fmt.Errorf("后端需要包含端口，例如 127.0.0.1:8080: %s", raw)
	}
	return strings.TrimSuffix(raw, "/"), nil
}

func NormalizeTCP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if IsDockerBackend(raw) {
		return canonicalDocker(raw)
	}
	raw = strings.TrimPrefix(raw, "tcp://")
	if raw == "" {
		return "", fmt.Errorf("tcp 后端地址为空")
	}
	if _, _, err := net.SplitHostPort(raw); err != nil {
		return "", fmt.Errorf("tcp 后端需要写成 host:port: %s", raw)
	}
	return raw, nil
}

func IsDockerBackend(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), "docker://")
}

func ParseDockerBackend(raw string) (name, port string, err error) {
	raw = strings.TrimSpace(raw)
	const prefix = "docker://"
	if !strings.HasPrefix(raw, prefix) {
		return "", "", fmt.Errorf("不是容器后端: %s", raw)
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(raw, prefix), "/")
	if rest == "" || strings.Contains(rest, "/") {
		return "", "", fmt.Errorf("容器后端需要写成 docker://容器名:端口，例如 docker://web:80")
	}
	name, port, err = net.SplitHostPort(rest)
	if err != nil || name == "" || strings.ContainsAny(name, " \t?#") {
		return "", "", fmt.Errorf("容器后端需要写成 docker://容器名:端口，例如 docker://web:80")
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("容器端口无效: %s", raw)
	}
	return name, strconv.Itoa(n), nil
}

func canonicalDocker(raw string) (string, error) {
	name, port, err := ParseDockerBackend(raw)
	if err != nil {
		return "", err
	}
	return "docker://" + name + ":" + port, nil
}

func UsesPort(proxies []Proxy, port int) bool {
	want := strconv.Itoa(port)
	for _, p := range proxies {
		_, got, err := splitListen(p.Listen)
		if err == nil && got == want {
			return true
		}
	}
	return false
}
