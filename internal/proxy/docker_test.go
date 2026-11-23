package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/billcoding/go-tls-proxy/internal/config"
	"github.com/billcoding/go-tls-proxy/internal/docker"
)

func TestDockerHTTPProxy(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("proto = %s", r.Header.Get("X-Forwarded-Proto"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	host, port, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/web/json" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"State":{"Running":true},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}}}}`, host)
	}))
	defer api.Close()

	handler, err := newHTTPHandler([]config.Route{{
		Path:    "/",
		Backend: "docker://web:" + port,
	}}, false, docker.NewClient(api.URL, api.Client()))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10/hello", nil)
	req.TLS = &tls.ConnectionState{}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || got != "/hello" {
		t.Fatalf("status=%d path=%s body=%s", rr.Code, got, rr.Body.String())
	}
}

func TestDockerHTTPNotRunning(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"State":{"Running":false},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}}}}`)
	}))
	defer api.Close()

	handler, err := newHTTPHandler([]config.Route{{
		Path:    "/",
		Backend: "docker://web:80",
	}}, false, docker.NewClient(api.URL, api.Client()))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestTCPResolveUsesShortCache(t *testing.T) {
	var hits atomic.Int32
	var ip atomic.Value
	ip.Store("10.9.0.4")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprintf(w, `{"State":{"Running":true},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}}}}`, ip.Load().(string))
	}))
	defer api.Close()
	resolver := docker.NewClient(api.URL, api.Client())

	for range 2 {
		addr, err := backendAddr(context.Background(), "docker://db:5432", resolver)
		if err != nil {
			t.Fatal(err)
		}
		if addr != "10.9.0.4:5432" {
			t.Fatalf("addr = %s", addr)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}

	ip.Store("10.9.0.8")
	resolver.Forget("db", "5432")
	addr, err := backendAddr(context.Background(), "docker://db:5432", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.9.0.8:5432" || hits.Load() != 2 {
		t.Fatalf("addr=%s hits=%d", addr, hits.Load())
	}

	addr, err = backendAddr(context.Background(), "127.0.0.1:9000", nil)
	if err != nil || addr != "127.0.0.1:9000" {
		t.Fatalf("static = %s err=%v", addr, err)
	}
}

func TestIsConnectFailure(t *testing.T) {
	timeoutErr := &net.OpError{Op: "dial", Err: timeoutNetError{}}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, true},
		{"no route", &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, true},
		{"unreachable", &net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, true},
		{"timeout", timeoutErr, true},
		{"dial deadline", &net.OpError{Op: "dial", Err: context.DeadlineExceeded}, true},
		{"canceled", &net.OpError{Op: "dial", Err: context.Canceled}, false},
		{"read reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, false},
		{"plain", errors.New("解析失败"), false},
	}
	for _, tc := range cases {
		if got := isConnectFailure(tc.err); got != tc.want {
			t.Errorf("%s = %v", tc.name, got)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	_, err = net.DialTimeout("tcp", net.JoinHostPort("::1", port), time.Second)
	if err == nil || !isConnectFailure(err) {
		t.Fatalf("real dial err = %v", err)
	}
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }

func TestDockerHTTPUsesShortCache(t *testing.T) {
	port := serveLocal(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	resolver, hits := dockerResolver(t, func(int32) (bool, string) {
		return true, "127.0.0.1"
	})
	handler := dockerHandler(t, port, resolver)

	for range 2 {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://203.0.113.10/", nil))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestDockerHTTPRedialsWhenIPChanges(t *testing.T) {
	var gotPath, gotHost, gotBody string
	port := serveLocal(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotHost = r.Host
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusNoContent)
	}))
	resolver, hits := dockerResolver(t, func(n int32) (bool, string) {
		if n == 1 {
			return true, "::1"
		}
		return true, "127.0.0.1"
	})
	handler := dockerHandler(t, port, resolver)

	req := httptest.NewRequest(http.MethodPost, "https://203.0.113.10/hello", strings.NewReader("abc"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || gotPath != "/hello" || gotBody != "abc" {
		t.Fatalf("status=%d path=%s body=%s resp=%s", rr.Code, gotPath, gotBody, rr.Body.String())
	}
	if gotHost != "127.0.0.1:"+port {
		t.Fatalf("host = %s", gotHost)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d", hits.Load())
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://203.0.113.10/again", nil))
	if rr.Code != http.StatusNoContent || hits.Load() != 2 {
		t.Fatalf("cached status=%d hits=%d", rr.Code, hits.Load())
	}
}

func TestDockerHTTPConnectFailureDropsCache(t *testing.T) {
	port := freePort(t)
	resolver, hits := dockerResolver(t, func(int32) (bool, string) {
		return true, "::1"
	})
	handler := dockerHandler(t, port, resolver)
	for range 2 {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://203.0.113.10/", nil))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status = %d", rr.Code)
		}
	}
	if hits.Load() != 4 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestDockerHTTPStoppedOnRefresh(t *testing.T) {
	port := freePort(t)
	resolver, hits := dockerResolver(t, func(n int32) (bool, string) {
		if n == 1 {
			return true, "::1"
		}
		return false, ""
	})
	handler := dockerHandler(t, port, resolver)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://203.0.113.10/", nil))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rr.Code)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestDockerHTTPReadErrorDoesNotRefresh(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resolver, hits := dockerResolver(t, func(int32) (bool, string) {
		return true, "127.0.0.1"
	})
	handler := dockerHandler(t, port, resolver)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "https://203.0.113.10/", nil))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rr.Code)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestTCPRedialsWhenIPChanges(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		got <- string(buf)
	}()

	resolver, hits := dockerResolver(t, func(n int32) (bool, string) {
		if n == 1 {
			return true, "::1"
		}
		return true, "127.0.0.1"
	})
	left, right := net.Pipe()
	defer left.Close()
	go tunnel(context.Background(), right, "db", "docker://db:"+port, resolver)

	_ = left.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := left.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-got:
		if body != "ping" {
			t.Fatalf("body = %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not accept")
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestTCPConnectFailureDropsCache(t *testing.T) {
	port := freePort(t)
	resolver, hits := dockerResolver(t, func(int32) (bool, string) {
		return true, "::1"
	})
	left, right := net.Pipe()
	defer left.Close()
	done := make(chan struct{})
	go func() {
		tunnel(context.Background(), right, "db", "docker://db:"+port, resolver)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel did not return")
	}
	if hits.Load() != 2 {
		t.Fatalf("hits = %d", hits.Load())
	}
	if _, err := resolver.Resolve(context.Background(), "db", port, false); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 3 {
		t.Fatalf("stale cache kept, hits = %d", hits.Load())
	}
}

func dockerResolver(t *testing.T, ipFor func(n int32) (bool, string)) (*docker.Resolver, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		running, ip := ipFor(hits.Add(1))
		state := "false"
		if running {
			state = "true"
		}
		fmt.Fprintf(w, `{"State":{"Running":%s},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":%q}}}}`, state, ip)
	}))
	t.Cleanup(api.Close)
	return docker.NewClient(api.URL, api.Client()), &hits
}

func dockerHandler(t *testing.T, port string, resolver *docker.Resolver) http.Handler {
	t.Helper()
	handler, err := newHTTPHandler([]config.Route{{
		Path:    "/",
		Backend: "docker://web:" + port,
	}}, false, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func serveLocal(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	return port
}
