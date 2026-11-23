package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadAndNormalize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	body := []byte(`
certificate:
  email: you@example.com
  ips: ["127.0.0.1"]
  renew_every: 3d
  staging: true
  challenge: tls-alpn-01
  http_port: 8080
  directory: https://old.example/directory
  web_root: /tmp/acme
  profile: classic
proxies:
  - name: web
    listen: ":443"
    backend: 127.0.0.1:8080
  - name: pg
    listen: ":8443"
    mode: tcp
    backend: 10.0.0.8:5432
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Certificate.RenewInterval != 72*time.Hour {
		t.Fatalf("renew = %s", cfg.Certificate.RenewInterval)
	}
	if cfg.Certificate.Staging || cfg.Certificate.Email != "" {
		t.Fatalf("certificate = %+v", cfg.Certificate)
	}
	if len(cfg.Certificate.IPs) != 1 || cfg.Certificate.IPs[0] != "auto" {
		t.Fatalf("ips = %#v", cfg.Certificate.IPs)
	}
	if cfg.Certificate.Challenge != "http-01" || cfg.Certificate.HTTPPort != 80 || cfg.Certificate.Profile != "shortlived" {
		t.Fatalf("challenge = %s port %d profile %s", cfg.Certificate.Challenge, cfg.Certificate.HTTPPort, cfg.Certificate.Profile)
	}
	if cfg.Certificate.Directory != "" {
		t.Fatalf("directory = %s", cfg.Certificate.Directory)
	}
	if cfg.Certificate.StorageDir != filepath.Join(dir, "data") {
		t.Fatalf("storage = %s", cfg.Certificate.StorageDir)
	}
	if cfg.Proxies[0].Routes[0].Path != "/" || cfg.Proxies[0].Routes[0].Backend != "http://127.0.0.1:8080" {
		t.Fatalf("route = %+v", cfg.Proxies[0].Routes)
	}
	if cfg.Proxies[0].TLS != nil || cfg.Proxies[0].PlainHTTP() {
		t.Fatalf("default tls = %+v plain=%v", cfg.Proxies[0].TLS, cfg.Proxies[0].PlainHTTP())
	}
	if cfg.Proxies[1].Backend != "10.0.0.8:5432" || cfg.Proxies[1].PlainHTTP() {
		t.Fatalf("tcp backend = %s plain=%v", cfg.Proxies[1].Backend, cfg.Proxies[1].PlainHTTP())
	}
	if cfg.Docker.Socket != "unix:///var/run/docker.sock" {
		t.Fatalf("docker = %+v", cfg.Docker)
	}
}

func TestRejectDuplicateListenAndExampleEmail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	body := []byte(`
certificate:
  ips: ["127.0.0.1"]
proxies:
  - listen: ":443"
    backend: 127.0.0.1:8080
  - listen: "0.0.0.0:443"
    backend: 127.0.0.1:8081
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDockerBackendConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	body := []byte(`
certificate:
  ips: ["127.0.0.1"]
docker:
  socket: unix:///tmp/docker-does-not-exist.sock
  network: appnet
proxies:
  - name: web
    listen: ":443"
    routes:
      - path: /api
        backend: docker://api:8080
      - path: /
        backend: "docker://My.Web_1:080"
  - name: pg
    listen: ":8443"
    mode: tcp
    backend: docker://postgres:5432
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Docker.Socket != "unix:///tmp/docker-does-not-exist.sock" {
		t.Fatalf("docker = %+v", cfg.Docker)
	}
	if cfg.Proxies[0].Routes[0].Backend != "docker://api:8080" {
		t.Fatalf("api = %s", cfg.Proxies[0].Routes[0].Backend)
	}
	if cfg.Proxies[0].Routes[1].Backend != "docker://My.Web_1:80" {
		t.Fatalf("web = %s", cfg.Proxies[0].Routes[1].Backend)
	}
	if cfg.Proxies[1].Backend != "docker://postgres:5432" {
		t.Fatalf("tcp = %s", cfg.Proxies[1].Backend)
	}

	name, port, err := ParseDockerBackend("docker://My.Web_1:080")
	if err != nil || name != "My.Web_1" || port != "80" {
		t.Fatalf("parse = %s %s %v", name, port, err)
	}
	got, err := NormalizeHTTPBackend("127.0.0.1:8080")
	if err != nil || got != "http://127.0.0.1:8080" {
		t.Fatalf("http = %s %v", got, err)
	}
	got, err = NormalizeTCP("tcp://10.0.0.8:5432")
	if err != nil || got != "10.0.0.8:5432" {
		t.Fatalf("tcp = %s %v", got, err)
	}
	if _, err := NormalizeHTTPBackend("docker://web"); err == nil {
		t.Fatal("missing port")
	}
	if _, err := NormalizeTCP("docker://:80"); err == nil {
		t.Fatal("missing name")
	}
}

func TestPlaceholderEmailAllowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	body := []byte(`
certificate:
  email: you@example.com
  ips: ["203.0.113.10"]
proxies:
  - listen: ":443"
    backend: 127.0.0.1:8080
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Certificate.Email != "" {
		t.Fatalf("email = %q", cfg.Certificate.Email)
	}
	if len(cfg.Certificate.IPs) != 1 || cfg.Certificate.IPs[0] != "auto" {
		t.Fatalf("ips = %#v", cfg.Certificate.IPs)
	}
	if err := os.WriteFile(path, []byte(`
certificate:
  ips: ["203.0.113.10"]
proxies:
  - listen: ":443"
    backend: 127.0.0.1:8080
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Certificate.Email != "" {
		t.Fatalf("empty email = %q", cfg.Certificate.Email)
	}
	if cfg.Certificate.Challenge != "http-01" {
		t.Fatalf("challenge = %s", cfg.Certificate.Challenge)
	}
	t.Setenv("GO_TLS_PROXY_ACME_DIRECTORY", "https://acme.example.test/directory")
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Certificate.Directory != "https://acme.example.test/directory" {
		t.Fatalf("directory = %s", cfg.Certificate.Directory)
	}
}

func TestPlainHTTPAndRedirectConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	body := []byte(`
proxies:
  - name: plain
    listen: ":8080"
    mode: http
    tls: false
    routes:
      - path: /go
        redirect: https://203.0.113.10/
        redirect_code: 301
      - path: /land
        redirect: https://203.0.113.10/landing
      - path: /
        backend: 127.0.0.1:8080
  - name: web
    listen: ":443"
    tls: true
    backend: 127.0.0.1:8081
  - name: legacy
    listen: ":8444"
    backend: 127.0.0.1:8082
  - name: extra
    listen: ":8443"
    mode: tcp
    tls: false
    backend: 127.0.0.1:9000
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	plain := cfg.Proxies[0]
	if !plain.PlainHTTP() || plain.TLS == nil || *plain.TLS {
		t.Fatalf("plain tls = %+v", plain.TLS)
	}
	if plain.Routes[0].Redirect != "https://203.0.113.10/" || plain.Routes[0].RedirectCode != 301 || plain.Routes[0].Backend != "" {
		t.Fatalf("301 = %+v", plain.Routes[0])
	}
	if plain.Routes[1].Redirect != "https://203.0.113.10/landing" || plain.Routes[1].RedirectCode != 302 || plain.Routes[1].Backend != "" {
		t.Fatalf("302 = %+v", plain.Routes[1])
	}
	if plain.Routes[2].Backend != "http://127.0.0.1:8080" || plain.Routes[2].Redirect != "" {
		t.Fatalf("backend = %+v", plain.Routes[2])
	}
	if cfg.Proxies[1].PlainHTTP() || cfg.Proxies[1].TLS == nil || !*cfg.Proxies[1].TLS || cfg.Proxies[1].Mode != ModeHTTP {
		t.Fatalf("explicit tls = %+v mode=%s", cfg.Proxies[1].TLS, cfg.Proxies[1].Mode)
	}
	if cfg.Proxies[2].TLS != nil || cfg.Proxies[2].PlainHTTP() || cfg.Proxies[2].Mode != ModeHTTP {
		t.Fatalf("default https = %+v mode=%s", cfg.Proxies[2].TLS, cfg.Proxies[2].Mode)
	}
	if cfg.Proxies[3].Mode != ModeTCP || cfg.Proxies[3].PlainHTTP() || cfg.Proxies[3].Backend != "127.0.0.1:9000" {
		t.Fatalf("tcp = %+v", cfg.Proxies[3])
	}
}

func TestRejectBadRedirect(t *testing.T) {
	cases := []string{
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
        redirect: https://203.0.113.10/
        redirect_code: 303
`,
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
        redirect: https://203.0.113.10/
        redirect_code: 200
`,
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
        redirect: https://203.0.113.10/
        redirect_code: 307
`,
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
        backend: 127.0.0.1:8080
        redirect: https://203.0.113.10/
`,
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
        redirect: /relative
        redirect_code: 301
`,
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
        redirect: ftp://203.0.113.10/
`,
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
`,
		`
proxies:
  - listen: ":8080"
    routes:
      - path: /
        redirect_code: 301
`,
	}
	for i, body := range cases {
		dir := t.TempDir()
		path := filepath.Join(dir, "go-tls-proxy.yml")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestNamedRedirectAndSharedListen(t *testing.T) {
	cfg, err := loadTemp(t, `
proxies:
  - name: minio9001http
    listen: ":9001"
    mode: http
    tls: false
    routes:
      - path: /land
        redirect: https://203.0.113.10/landing?from=old
        redirect_code: 301
      - path: /
        redirect: minio9001
  - name: minio9001
    listen: ":9001"
    mode: http
    backend: docker://minio:9001
  - name: alt
    listen: ":9080"
    mode: http
    tls: false
    routes:
      - path: /
        redirect: minio9001
        redirect_code: 301
  - name: plain-target
    listen: ":9082"
    tls: false
    backend: 127.0.0.1:9
  - name: to-plain
    listen: ":9083"
    tls: false
    routes:
      - path: /
        redirect: plain-target
  - name: explicit
    listen: ":9443"
    tls: true
    backend: 127.0.0.1:9
  - name: to-explicit
    listen: ":9444"
    tls: false
    routes:
      - path: /
        redirect: explicit
`)
	if err != nil {
		t.Fatal(err)
	}
	plain := cfg.Proxies[0]
	if !plain.PlainHTTP() {
		t.Fatal("plain http")
	}
	if plain.Routes[0].Redirect != "https://203.0.113.10/landing?from=old" || plain.Routes[0].RedirectCode != 301 || plain.Routes[0].RedirectTo != nil {
		t.Fatalf("absolute = %+v", plain.Routes[0])
	}
	named := plain.Routes[1]
	if named.Redirect != "minio9001" || named.RedirectCode != 302 || named.Backend != "" || named.RedirectTo == nil {
		t.Fatalf("named = %+v", named)
	}
	if named.RedirectTo.Scheme != "https" || named.RedirectTo.Port != "9001" {
		t.Fatalf("target = %+v", named.RedirectTo)
	}
	https := cfg.Proxies[1]
	if https.PlainHTTP() || https.Mode != ModeHTTP || https.Routes[0].Backend != "docker://minio:9001" {
		t.Fatalf("https = %+v", https)
	}
	alt := cfg.Proxies[2].Routes[0]
	if alt.RedirectCode != 301 || alt.RedirectTo == nil || alt.RedirectTo.Scheme != "https" || alt.RedirectTo.Port != "9001" {
		t.Fatalf("cross port = %+v", alt)
	}
	toPlain := cfg.Proxies[4].Routes[0]
	if toPlain.RedirectTo == nil || toPlain.RedirectTo.Scheme != "http" || toPlain.RedirectTo.Port != "9082" {
		t.Fatalf("plain target = %+v", toPlain.RedirectTo)
	}
	toExplicit := cfg.Proxies[6].Routes[0]
	if toExplicit.RedirectTo == nil || toExplicit.RedirectTo.Scheme != "https" || toExplicit.RedirectTo.Port != "9443" {
		t.Fatalf("explicit tls = %+v", toExplicit.RedirectTo)
	}
}

func TestRejectNamedRedirectAndListen(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "missing",
			want: "找不到代理 nope",
			body: `
proxies:
  - name: plain
    listen: ":8080"
    tls: false
    routes:
      - path: /
        redirect: nope
`,
		},
		{
			name: "self",
			want: "不能指向自己",
			body: `
proxies:
  - name: plain
    listen: ":8080"
    tls: false
    routes:
      - path: /
        redirect: plain
`,
		},
		{
			name: "tcp",
			want: "不能指向 tcp",
			body: `
proxies:
  - name: plain
    listen: ":8080"
    tls: false
    routes:
      - path: /
        redirect: extra
  - name: extra
    listen: ":8443"
    mode: tcp
    backend: 127.0.0.1:9000
`,
		},
		{
			name: "duplicate",
			want: "代理名字重复: web",
			body: `
proxies:
  - name: web
    listen: ":8080"
    backend: 127.0.0.1:1
  - name: web
    listen: ":8081"
    backend: 127.0.0.1:2
`,
		},
		{
			name: "two https",
			want: "监听地址冲突",
			body: `
proxies:
  - name: a
    listen: ":9001"
    backend: 127.0.0.1:1
  - name: b
    listen: ":9001"
    tls: true
    backend: 127.0.0.1:2
`,
		},
		{
			name: "two plain",
			want: "监听地址冲突",
			body: `
proxies:
  - name: a
    listen: ":9001"
    tls: false
    backend: 127.0.0.1:1
  - name: b
    listen: ":9001"
    tls: false
    backend: 127.0.0.1:2
`,
		},
		{
			name: "wildcard",
			want: "监听地址冲突",
			body: `
proxies:
  - name: a
    listen: ":9001"
    tls: false
    backend: 127.0.0.1:1
  - name: b
    listen: "127.0.0.1:9001"
    backend: 127.0.0.1:2
`,
		},
		{
			name: "tcp same port",
			want: "监听地址冲突",
			body: `
proxies:
  - name: a
    listen: ":9001"
    tls: false
    routes:
      - path: /
        redirect: b
  - name: b
    listen: ":9001"
    mode: tcp
    backend: 127.0.0.1:9
`,
		},
		{
			name: "port 80",
			want: "http-01",
			body: `
proxies:
  - name: a
    listen: ":80"
    tls: false
    routes:
      - path: /
        redirect: b
  - name: b
    listen: ":443"
    backend: 127.0.0.1:9
`,
		},
		{
			name: "bad code",
			want: "redirect_code",
			body: `
proxies:
  - name: a
    listen: ":8080"
    tls: false
    routes:
      - path: /
        redirect: b
        redirect_code: 303
  - name: b
    listen: ":443"
    backend: 127.0.0.1:9
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadTemp(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func loadTemp(t *testing.T, body string) (*File, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestRejectBadDockerSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go-tls-proxy.yml")
	body := []byte(`
certificate:
  ips: ["127.0.0.1"]
docker:
  socket: tcp://127.0.0.1:2375
proxies:
  - listen: ":443"
    backend: 127.0.0.1:8080
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
}
