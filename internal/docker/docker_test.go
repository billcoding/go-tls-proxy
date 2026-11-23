package docker

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeSocket(t *testing.T) {
	got, err := NormalizeSocket("")
	if err != nil || got != DefaultSocket {
		t.Fatalf("default = %q err=%v", got, err)
	}
	got, err = NormalizeSocket(" /var/run/docker.sock ")
	if err != nil || got != "/var/run/docker.sock" {
		t.Fatalf("path = %q err=%v", got, err)
	}
	if _, err := NormalizeSocket("tcp://127.0.0.1:2375"); err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveContainerIP(t *testing.T) {
	const body = `{
		"State": {"Running": true},
		"NetworkSettings": {"Networks": {
			"none": {"IPAddress": ""},
			"bridge": {"IPAddress": "172.17.0.2"},
			"app": {"IPAddress": "10.0.1.5", "GlobalIPv6Address": "fd00::5"}
		}}
	}`
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/web/json" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	defer api.Close()

	resolver := NewClient(api.URL, api.Client())
	addr, err := resolver.Resolve(context.Background(), "web", "80", true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "172.17.0.2:80" {
		t.Fatalf("addr = %s，应使用第一个有地址的网络", addr)
	}
}

func TestResolveIPv6AndMissingNetwork(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{
			"State": {"Running": true},
			"NetworkSettings": {"Networks": {
				"bridge": {"IPAddress": "", "GlobalIPv6Address": "fd00::10"}
			}}
		}`)
	}))
	defer api.Close()

	resolver := NewClient(api.URL, api.Client())
	addr, err := resolver.Resolve(context.Background(), "web", "443", true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "[fd00::10]:443" {
		t.Fatalf("addr = %s", addr)
	}
}

func TestContainerNotRunningOrMissing(t *testing.T) {
	var running atomic.Bool
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/containers/web/json":
			state := "false"
			if running.Load() {
				state = "true"
			}
			_, _ = fmt.Fprintf(w, `{"State":{"Running":%s},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"10.0.0.8"}}}}`, state)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	resolver := NewClient(api.URL, api.Client())
	_, err := resolver.Resolve(context.Background(), "web", "80", true)
	if err == nil || !strings.Contains(err.Error(), "未运行") {
		t.Fatalf("stopped = %v", err)
	}
	_, err = resolver.Resolve(context.Background(), "missing", "80", true)
	if err == nil || !strings.Contains(err.Error(), "找不到容器 missing") {
		t.Fatalf("missing = %v", err)
	}

	running.Store(true)
	addr, err := resolver.Resolve(context.Background(), "web", "5432", true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.0.0.8:5432" {
		t.Fatalf("addr = %s", addr)
	}
}

func TestResolveCacheAndFresh(t *testing.T) {
	var hits atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, `{"State":{"Running":true},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.9"}}}}`)
	}))
	defer api.Close()

	resolver := NewClient(api.URL, api.Client())
	resolver.ttl = time.Hour
	ctx := context.Background()
	if _, err := resolver.Resolve(ctx, "web", "80", false); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, "web", "80", false); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("cached hits = %d", hits.Load())
	}
	if _, err := resolver.Resolve(ctx, "web", "80", true); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("fresh hits = %d", hits.Load())
	}
}

func TestForgetDropsCache(t *testing.T) {
	var hits atomic.Int32
	var ip atomic.Value
	ip.Store("172.17.0.2")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintf(w, `{"State":{"Running":true},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}}}}`, ip.Load().(string))
	}))
	defer api.Close()

	resolver := NewClient(api.URL, api.Client())
	resolver.ttl = time.Hour
	ctx := context.Background()
	addr, err := resolver.Resolve(ctx, "web", "80", false)
	if err != nil || addr != "172.17.0.2:80" {
		t.Fatalf("addr=%s err=%v", addr, err)
	}
	if _, err := resolver.Resolve(ctx, "web", "80", false); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("cached hits = %d", hits.Load())
	}

	ip.Store("172.17.0.9")
	resolver.Forget("web", "80")
	addr, err = resolver.Resolve(ctx, "web", "80", false)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "172.17.0.9:80" || hits.Load() != 2 {
		t.Fatalf("after forget addr=%s hits=%d", addr, hits.Load())
	}

	if _, err := resolver.Resolve(ctx, "web", "8080", false); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 3 {
		t.Fatalf("other port reused cache, hits=%d", hits.Load())
	}
}

func TestResolveUnixSocket(t *testing.T) {
	sock := fmt.Sprintf("/tmp/ghp-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	_ = os.Remove(sock)
	t.Cleanup(func() { _ = os.Remove(sock) })

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/web/json" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"State":{"Running":true},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.9"}}}}`)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	resolver, err := New("unix://" + sock)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := resolver.Resolve(context.Background(), "web", "80", true)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "172.17.0.9:80" {
		t.Fatalf("addr = %s", addr)
	}
}

func TestResolveSingleflight(t *testing.T) {
	var hits atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			close(started)
			<-release
		}
		_, _ = io.WriteString(w, `{"State":{"Running":true},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"10.1.0.7"}}}}`)
	}))
	defer api.Close()

	resolver := NewClient(api.URL, api.Client())
	resolver.ttl = time.Hour
	const n = 8
	start := make(chan struct{})
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			<-start
			addr, err := resolver.Resolve(context.Background(), "web", "80", false)
			if err != nil {
				errCh <- err
				return
			}
			if addr != "10.1.0.7:80" {
				errCh <- fmt.Errorf("addr = %s", addr)
			}
		}()
	}
	close(start)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("lookup did not start")
	}
	time.Sleep(50 * time.Millisecond)
	if hits.Load() != 1 {
		t.Fatalf("hits before release = %d", hits.Load())
	}
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
}
