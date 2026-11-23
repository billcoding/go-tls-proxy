package cert

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKnownChallengeDirs(t *testing.T) {
	if len(knownChallengeDirs) != 1 || knownChallengeDirs[0] != "/var/www/go-tls-proxy/.well-known/acme-challenge" {
		t.Fatalf("dirs = %#v", knownChallengeDirs)
	}
}

func TestOpenHTTP01WritesWebRootWhenBusy(t *testing.T) {
	restoreHTTP01Hooks(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "acme")
	nginxRunning = func() bool { return false }
	listenTCP = func(string, string) (net.Listener, error) {
		return nil, errors.New("bind: address already in use")
	}
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	m := NewManager(Options{
		StorageDir: dir,
		Challenge:  "http-01",
		HTTPPort:   80,
		WebRoot:    root,
		IPs:        []net.IP{net.ParseIP("203.0.113.10")},
	})
	stop, err := m.openHTTP01(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	m.http01.Set("/.well-known/acme-challenge/token-ok", "payload")
	got, err := os.ReadFile(filepath.Join(root, "token-ok"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("file = %q %v", got, err)
	}
	m.http01.Set("/.well-known/acme-challenge/../etc/passwd", "inside")
	if _, err := os.Stat(filepath.Join(dir, "etc", "passwd")); !os.IsNotExist(err) {
		t.Fatal("token 路径穿越")
	}
	inside, err := os.ReadFile(filepath.Join(root, "passwd"))
	if err != nil || string(inside) != "inside" {
		t.Fatalf("最后一段应留在校验目录: %q %v", inside, err)
	}
	m.http01.Clear()
	if _, err := os.Stat(filepath.Join(root, "token-ok")); !os.IsNotExist(err) {
		t.Fatal("校验文件没有清掉")
	}
}

func TestOpenHTTP01SkipsBindWhenNginxServesChallenge(t *testing.T) {
	restoreHTTP01Hooks(t)
	dir := t.TempDir()
	root := filepath.Join(dir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	knownChallengeDirs = []string{root}
	nginxRunning = func() bool { return true }
	listenTCP = func(string, string) (net.Listener, error) {
		t.Fatal("nginx 已提供校验目录时不应绑定端口")
		return nil, nil
	}
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	m := NewManager(Options{
		StorageDir: dir,
		Challenge:  "http-01",
		IPs:        []net.IP{net.ParseIP("203.0.113.10")},
	})
	stop, err := m.openHTTP01(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stop()
}

func TestOpenHTTP01DropsFirewallWhenListenFails(t *testing.T) {
	restoreHTTP01Hooks(t)
	dir := t.TempDir()
	var calls []string
	nginxRunning = func() bool { return false }
	listenTCP = func(string, string) (net.Listener, error) {
		return nil, errors.New("permission denied")
	}
	lookPath = only("iptables")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "-C" {
			return nil, errors.New("missing")
		}
		return nil, nil
	}
	m := NewManager(Options{
		StorageDir: dir,
		Challenge:  "http-01",
		HTTPPort:   80,
		IPs:        []net.IP{net.ParseIP("203.0.113.10")},
	})
	if _, err := m.openHTTP01(context.Background()); err == nil {
		t.Fatal("监听失败应返回错误")
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "-I INPUT 1") || !strings.Contains(joined, "-D INPUT") {
		t.Fatal(joined)
	}
	if _, err := os.Stat(filepath.Join(dir, "port80.open")); !os.IsNotExist(err) {
		t.Fatal("失败后标记文件还在")
	}
}

func TestLockDir(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	unlock, err = lockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

func restoreHTTP01Hooks(t *testing.T) {
	t.Helper()
	oldNginx, oldListen, oldDirs := nginxRunning, listenTCP, append([]string(nil), knownChallengeDirs...)
	oldExec, oldLook := execCommand, lookPath
	oldExe := executablePath
	oldEscalate := firewallEscalate
	firewallEscalate = true
	executablePath = func() (string, error) {
		return filepath.Join(t.TempDir(), "go-tls-proxy"), nil
	}
	t.Cleanup(func() {
		nginxRunning = oldNginx
		listenTCP = oldListen
		knownChallengeDirs = oldDirs
		execCommand = oldExec
		lookPath = oldLook
		executablePath = oldExe
		firewallEscalate = oldEscalate
	})
}
