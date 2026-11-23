package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/billcoding/go-tls-proxy/internal/cert"
	"github.com/billcoding/go-tls-proxy/internal/config"
)

func TestHTTPSAndTCPProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("proto = %s", r.Header.Get("X-Forwarded-Proto"))
		}
		_, _ = io.WriteString(w, "web:"+r.URL.Path)
	}))
	defer backend.Close()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	manager := testManager(t)

	server, err := New([]config.Proxy{
		{
			Name:   "web",
			Listen: "127.0.0.1:0",
			Mode:   config.ModeHTTP,
			Routes: []config.Route{{Path: "/", Backend: backend.URL}},
		},
		{
			Name:    "tcp",
			Listen:  "127.0.0.1:0",
			Mode:    config.ModeTCP,
			Backend: echo.Addr().String(),
		},
	}, manager.TLSConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					leaf, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return err
					}
					if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
						t.Errorf("证书 IP = %v", leaf.IPAddresses)
					}
					return nil
				},
			},
		},
	}
	resp, err := client.Get("https://" + server.httpLns[0].Addr().String() + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "web:/hello" {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}

	conn, err := tls.Dial("tcp", server.tcp[0].ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("ping"), 64<<10)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tcp len = %d", len(got))
	}
	if proto := conn.ConnectionState().NegotiatedProtocol; proto != "http/1.1" {
		t.Fatalf("tcp alpn = %q", proto)
	}
}

func TestPlainHTTPRedirectAndDefaultTLS(t *testing.T) {
	var gotPath, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotProto = r.Header.Get("X-Forwarded-Proto")
		_, _ = io.WriteString(w, "web:"+r.URL.Path)
	}))
	defer backend.Close()

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	manager := testManager(t)

	plain := false
	server, err := New([]config.Proxy{
		{
			Name:   "plain",
			Listen: "127.0.0.1:0",
			Mode:   config.ModeHTTP,
			TLS:    &plain,
			Routes: []config.Route{
				{Path: "/old", Redirect: "https://203.0.113.10/", RedirectCode: http.StatusMovedPermanently},
				{Path: "/land", Redirect: "https://203.0.113.10/landing", RedirectCode: http.StatusFound},
				{Path: "/", Backend: backend.URL},
			},
		},
		{
			Name:   "https",
			Listen: "127.0.0.1:0",
			Mode:   config.ModeHTTP,
			Routes: []config.Route{{Path: "/", Backend: backend.URL}},
		},
		{
			Name:    "tcp",
			Listen:  "127.0.0.1:0",
			Mode:    config.ModeTCP,
			TLS:     &plain,
			Backend: echo.Addr().String(),
		},
	}, manager.TLSConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + server.httpLns[0].Addr().String() + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "web:/hello" || gotPath != "/hello" || gotProto != "http" {
		t.Fatalf("plain status=%d body=%s path=%s proto=%s", resp.StatusCode, body, gotPath, gotProto)
	}

	resp, err = client.Get("http://" + server.httpLns[0].Addr().String() + "/old/a/b?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "https://203.0.113.10/old/a/b?x=1" {
		t.Fatalf("301 status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, err = client.Get("http://" + server.httpLns[0].Addr().String() + "/land/z?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://203.0.113.10/landing?x=1" {
		t.Fatalf("302 status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	httpsClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err = httpsClient.Get("https://" + server.httpLns[1].Addr().String() + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "web:/hello" || gotProto != "https" {
		t.Fatalf("https status=%d body=%s proto=%s", resp.StatusCode, body, gotProto)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+server.httpLns[1].Addr().String()+"/hello", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("default http mode accepted plaintext")
	}

	conn, err := tls.Dial("tcp", server.tcp[0].ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("tcp = %q", got)
	}
}

func TestSharedPortNamedRedirect(t *testing.T) {
	var gotPath, gotProto string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotProto = r.Header.Get("X-Forwarded-Proto")
		_, _ = io.WriteString(w, "web:"+r.URL.Path)
	}))
	defer backend.Close()

	shared := freeAddr(t)
	other := freeAddr(t)
	_, sharedPort, err := net.SplitHostPort(shared)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	body := fmt.Sprintf(`
proxies:
  - name: minio9001http
    listen: %q
    mode: http
    tls: false
    routes:
      - path: /
        redirect: minio9001
  - name: minio9001
    listen: %q
    mode: http
    backend: %q
  - name: alt
    listen: %q
    mode: http
    tls: false
    routes:
      - path: /
        redirect: minio9001
        redirect_code: 301
`, shared, shared, backend.URL, other)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[0].Routes[0].RedirectTo == nil || cfg.Proxies[0].Routes[0].RedirectTo.Port != sharedPort {
		t.Fatalf("redirect = %+v", cfg.Proxies[0].Routes[0])
	}

	manager := testManager(t)
	server, err := New(cfg.Proxies, manager.TLSConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+shared+"/a/b?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "203.0.113.10:9080"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := "https://203.0.113.10:" + sharedPort + "/a/b?x=1"
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
		t.Fatalf("shared status=%d loc=%q want %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}

	req, err = http.NewRequest(http.MethodGet, "http://"+other+"/a/b?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "203.0.113.10:9080"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != want {
		t.Fatalf("cross status=%d loc=%q want %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}

	httpsClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err = httpsClient.Get("https://" + shared + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(payload) != "web:/hello" || gotPath != "/hello" || gotProto != "https" {
		t.Fatalf("https status=%d body=%s path=%s proto=%s", resp.StatusCode, payload, gotPath, gotProto)
	}

	resp, err = client.Get("http://" + shared + "/z?q=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://127.0.0.1:"+sharedPort+"/z?q=1" {
		t.Fatalf("again status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	raw, err := net.Dial("tcp", shared)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := fmt.Fprintf(raw, "GET /a/b?x=1 HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	status, loc := readStatusAndLocation(t, raw)
	if !strings.Contains(status, "302") || loc != "https://127.0.0.1:"+sharedPort+"/a/b?x=1" {
		t.Fatalf("empty host status=%q loc=%q", status, loc)
	}
}

func TestHostFromCertificate(t *testing.T) {
	if got := hostFromCertificate(nil); got != "" {
		t.Fatalf("nil = %q", got)
	}
	manager := testManager(t)
	if got := hostFromCertificate(manager.TLSConfig()); got != "127.0.0.1" {
		t.Fatalf("host = %s", got)
	}
	provider := cert.NewProvider()
	crt, err := testTLSCert([]net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("203.0.113.10")})
	if err != nil {
		t.Fatal(err)
	}
	provider.SetCertificate(crt)
	if got := hostFromCertificate(provider.TLSConfig()); got != "203.0.113.10" {
		t.Fatalf("prefer v4 = %s", got)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func readStatusAndLocation(t *testing.T, conn net.Conn) (string, string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var loc string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "location:") {
			loc = strings.TrimSpace(line[len("location:"):])
		}
	}
	return strings.TrimSpace(status), loc
}

func testManager(t *testing.T) *cert.Manager {
	t.Helper()
	p := cert.NewProvider()
	crt, err := testTLSCert([]net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCertificate(crt)
	return cert.NewManager(cert.Options{
		Provider:   p,
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
		StorageDir: t.TempDir(),
		RenewEvery: 72 * time.Hour,
	})
}

// testTLSCert 只给代理测试做 TLS 握手，不走证书申请。
func testTLSCert(ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: ips[0].String()},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
