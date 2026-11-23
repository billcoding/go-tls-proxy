package cert

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	ipv4Endpoints = []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipv4.icanhazip.com",
		"https://icanhazip.com",
		"https://checkip.amazonaws.com",
		"https://1.1.1.1/cdn-cgi/trace",
	}
	ipv6Endpoints = []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
	}
)

// ResolveIPs 把配置里的 auto 和具体地址解析成证书要用的 IP。
func ResolveIPs(ctx context.Context, specs []string) ([]net.IP, error) {
	seen := map[string]struct{}{}
	var out []net.IP
	var errs []string
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		switch strings.ToLower(spec) {
		case "auto", "public":
			ips, err := detectPublic(ctx)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			for _, ip := range ips {
				out = addIP(out, seen, ip)
			}
		default:
			ip := net.ParseIP(spec)
			if ip == nil {
				return nil, fmt.Errorf("无法解析 IP %q", spec)
			}
			out = addIP(out, seen, ip)
		}
	}
	if len(out) == 0 {
		if len(errs) > 0 {
			return nil, fmt.Errorf("没有得到可用的 IP: %s", strings.Join(errs, "; "))
		}
		return nil, fmt.Errorf("没有得到可用的 IP")
	}
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i], out[j]) < 0
	})
	return out, nil
}

func addIP(dst []net.IP, seen map[string]struct{}, ip net.IP) []net.IP {
	ip = canonicalIP(ip)
	key := ip.String()
	if _, ok := seen[key]; ok {
		return dst
	}
	seen[key] = struct{}{}
	return append(dst, ip)
}

func canonicalIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...)
	}
	return append(net.IP(nil), ip.To16()...)
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func publicIPOverride() (string, string) {
	if v := strings.TrimSpace(os.Getenv("GO_TLS_PROXY_PUBLIC_IP")); v != "" {
		return v, "GO_TLS_PROXY_PUBLIC_IP"
	}
	return "", ""
}

func detectPublic(ctx context.Context) ([]net.IP, error) {
	if v, name := publicIPOverride(); v != "" {
		ip, err := parsePublicIP(v)
		if err != nil {
			return nil, fmt.Errorf("%s 不是公网 IP: %s", name, v)
		}
		return []net.IP{ip}, nil
	}
	var out []net.IP
	v4, err4 := fetchIP(ctx, ipv4Endpoints)
	if err4 == nil {
		out = append(out, v4)
	}
	v6, err6 := fetchIP(ctx, ipv6Endpoints)
	if err6 == nil && v6.To4() == nil {
		out = append(out, v6)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("查询公网 IP 失败: %v", err4)
	}
	return out, nil
}

func fetchIP(ctx context.Context, endpoints []string) (net.IP, error) {
	var last error
	client := &http.Client{Timeout: 8 * time.Second}
	for _, endpoint := range endpoints {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ip, err := fetchOne(reqCtx, client, endpoint)
		cancel()
		if err == nil {
			return ip, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("没有可用的查询地址")
	}
	return nil, last
}

func fetchOne(ctx context.Context, client *http.Client, endpoint string) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "curl/8.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s 返回 %s", endpoint, resp.Status)
	}
	ip, err := parsePublicIP(string(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", endpoint, err)
	}
	return ip, nil
}

// parsePublicIP 从一行地址或 Cloudflare trace 的 ip= 行里取出公网 IP。
func parsePublicIP(body string) (net.IP, error) {
	body = strings.TrimSpace(body)
	if ip, ok := usablePublic(body); ok {
		return ip, nil
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if len(line) > 3 && strings.EqualFold(line[:3], "ip=") {
			if ip, ok := usablePublic(line[3:]); ok {
				return ip, nil
			}
		}
	}
	return nil, fmt.Errorf("响应不是公网 IP")
}

func usablePublic(s string) (net.IP, bool) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if !PublicIP(ip) {
		return nil, false
	}
	return canonicalIP(ip), true
}

// PublicIP 报告这个地址能不能用于 Let's Encrypt 的 IP 证书。
func PublicIP(ip net.IP) bool {
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}
	return true
}
