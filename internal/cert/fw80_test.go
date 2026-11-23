package cert

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFW80ArgRules(t *testing.T) {
	if !validPort("1") || !validPort("80") || !validPort("65535") {
		t.Fatal("合法端口应通过")
	}
	for _, bad := range []string{"", "0", "65536", "08", "80/tcp", "-1"} {
		if validPort(bad) {
			t.Fatalf("端口 %q 不应通过", bad)
		}
	}
	if !closeArgsOK([]string{"iptables", "80"}) ||
		!closeArgsOK([]string{"firewalld", "80"}) ||
		!closeArgsOK([]string{"ufw", "443"}) ||
		!closeArgsOK([]string{"nft", "inet", "filter", "input", "80"}) {
		t.Fatal("合法 close 应通过")
	}
	for _, args := range [][]string{
		{"iptables"},
		{"iptables", "80", "extra"},
		{"iptables", "0"},
		{"bash", "-c"},
		{"ufw", "--force"},
		{"nft", "inet", "filter", "input"},
		{"nft", "../x", "filter", "input", "80"},
		{"nft", "inet", "filter", "input", "80", "extra"},
	} {
		if closeArgsOK(args) {
			t.Fatalf("close 不应通过 %#v", args)
		}
	}
	if !purgeArgsOK(nil) || !purgeArgsOK([]string{"iptables"}) || !purgeArgsOK([]string{"ufw"}) || !purgeArgsOK([]string{"nft"}) {
		t.Fatal("合法 purge 应通过")
	}
	if purgeArgsOK([]string{"all"}) || purgeArgsOK([]string{"iptables", "extra"}) || purgeArgsOK([]string{"firewall-cmd"}) {
		t.Fatal("非法 purge 应拒绝")
	}
}

func TestFW80RejectsWithoutRunningCommands(t *testing.T) {
	restoreExec(t)
	var calls []string
	lookPath = only("iptables", "firewall-cmd", "ufw", "nft")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, errors.New("missing")
	}
	cases := [][]string{
		nil,
		{"open"},
		{"open", "0"},
		{"open", "80", "extra"},
		{"open", "65536"},
		{"open", "08"},
		{"open", "-1"},
		{"close"},
		{"close", "iptables"},
		{"close", "iptables", "0"},
		{"close", "iptables", "80", "extra"},
		{"close", "bash", "-c", "id"},
		{"close", "ufw", "--force", "delete", "1"},
		{"close", "nft", "inet", "filter", "input"},
		{"close", "nft", "bad/name", "filter", "input", "80"},
		{"close", "purge", "all"},
		{"close", "purge", "iptables", "extra"},
		{"iptables", "-F"},
		{"firewall-cmd", "--add-port=80/tcp"},
		{"ufw-purge-ours"},
		{"nft-del-ours", "inet", "filter", "input"},
	}
	for _, args := range cases {
		if code := RunFW80(args); code == 0 {
			t.Fatalf("应拒绝 %#v", args)
		}
	}
	if len(calls) != 0 {
		t.Fatalf("拒绝参数时执行了命令: %s", strings.Join(calls, "\n"))
	}
}

func TestFW80OpenClosePicksCommands(t *testing.T) {
	t.Run("iptables", func(t *testing.T) {
		restoreExec(t)
		var calls []string
		lookPath = only("iptables")
		execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if len(args) > 0 && args[0] == "-C" {
				return nil, errors.New("missing")
			}
			return nil, nil
		}
		out := captureStdout(t, func() {
			if code := RunFW80([]string{"open", "80"}); code != 0 {
				t.Fatalf("open exit %d", code)
			}
		})
		if strings.TrimSpace(out) != "iptables 80" {
			t.Fatalf("stdout %q", out)
		}
		if code := RunFW80([]string{"close", "iptables", "80"}); code != 0 {
			t.Fatalf("close exit %d", code)
		}
		joined := strings.Join(calls, "\n")
		if !strings.Contains(joined, "iptables -I INPUT 1 -p tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT") {
			t.Fatal(joined)
		}
		if !strings.Contains(joined, "iptables -D INPUT -p tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT") {
			t.Fatal(joined)
		}
		if strings.Contains(joined, "sudo ") {
			t.Fatal(joined)
		}
	})

	t.Run("firewalld", func(t *testing.T) {
		restoreExec(t)
		var calls []string
		lookPath = only("firewall-cmd")
		execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "--state") {
				return []byte("running\n"), nil
			}
			if strings.Contains(joined, "--query-port") {
				return nil, errors.New("no")
			}
			return []byte("success\n"), nil
		}
		out := captureStdout(t, func() {
			if code := RunFW80([]string{"open", "80"}); code != 0 {
				t.Fatalf("open exit %d", code)
			}
		})
		if strings.TrimSpace(out) != "firewalld 80" {
			t.Fatalf("stdout %q", out)
		}
		if code := RunFW80([]string{"close", "firewalld", "80"}); code != 0 {
			t.Fatalf("close exit %d", code)
		}
		joined := strings.Join(calls, "\n")
		if !strings.Contains(joined, "firewall-cmd --add-port=80/tcp") ||
			!strings.Contains(joined, "firewall-cmd --remove-port=80/tcp") ||
			!strings.Contains(joined, "firewall-cmd --permanent --remove-port=80/tcp") {
			t.Fatal(joined)
		}
		if strings.Contains(joined, "--add-service") || strings.Contains(joined, "sudo ") {
			t.Fatal(joined)
		}
	})

	t.Run("ufw", func(t *testing.T) {
		restoreExec(t)
		var calls []string
		added := false
		lookPath = only("ufw")
		execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if args[0] == "status" && len(args) == 1 {
				return []byte("Status: active\n"), nil
			}
			if args[0] == "status" {
				if !added {
					return []byte("Status: active\n[ 1] 22/tcp ALLOW IN Anywhere\n"), nil
				}
				return []byte("Status: active\n[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 80/tcp ALLOW IN Anywhere # go-tls-proxy\n"), nil
			}
			if len(args) >= 2 && args[1] == "allow" {
				added = true
				return nil, nil
			}
			return nil, nil
		}
		out := captureStdout(t, func() {
			if code := RunFW80([]string{"open", "80"}); code != 0 {
				t.Fatalf("open exit %d", code)
			}
		})
		if strings.TrimSpace(out) != "ufw 80" {
			t.Fatalf("stdout %q", out)
		}
		if code := RunFW80([]string{"close", "ufw", "80"}); code != 0 {
			t.Fatalf("close exit %d", code)
		}
		joined := strings.Join(calls, "\n")
		if !strings.Contains(joined, "ufw --force allow 80/tcp comment go-tls-proxy") ||
			!strings.Contains(joined, "ufw --force delete 2") {
			t.Fatal(joined)
		}
		if strings.Contains(joined, "delete 1") {
			t.Fatal(joined)
		}
	})

	t.Run("nft", func(t *testing.T) {
		restoreExec(t)
		var calls []string
		lookPath = only("nft")
		ruleset := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"
		listed := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept # handle 2\n\t\ttcp dport 80 accept comment \"go-tls-proxy\" # handle 9\n\t}\n}\n"
		execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if name == "nft" && len(args) >= 2 && args[0] == "list" {
				return []byte(ruleset), nil
			}
			if name == "nft" && len(args) >= 2 && args[0] == "-a" {
				return []byte(listed), nil
			}
			return nil, nil
		}
		out := captureStdout(t, func() {
			if code := RunFW80([]string{"open", "80"}); code != 0 {
				t.Fatalf("open exit %d", code)
			}
		})
		if strings.TrimSpace(out) != "nft inet filter input 80" {
			t.Fatalf("stdout %q", out)
		}
		if code := RunFW80([]string{"close", "nft", "inet", "filter", "input", "80"}); code != 0 {
			t.Fatalf("close exit %d", code)
		}
		joined := strings.Join(calls, "\n")
		if !strings.Contains(joined, "nft insert rule inet filter input tcp dport 80 accept comment \"go-tls-proxy\"") {
			t.Fatal(joined)
		}
		if !strings.Contains(joined, "nft delete rule inet filter input handle 9") {
			t.Fatal(joined)
		}
		if strings.Contains(joined, "handle 2") {
			t.Fatal(joined)
		}
	})

	t.Run("purge", func(t *testing.T) {
		restoreExec(t)
		var calls []string
		lookPath = only("iptables")
		execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			if len(args) >= 1 && args[0] == "-S" {
				return []byte("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT\n"), nil
			}
			return nil, nil
		}
		if code := RunFW80([]string{"close", "purge", "iptables"}); code != 0 {
			t.Fatalf("purge exit %d", code)
		}
		joined := strings.Join(calls, "\n")
		if !strings.Contains(joined, "-D INPUT -p tcp -m tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT") {
			t.Fatal(joined)
		}
		if strings.Contains(joined, "--dport 22") && strings.Contains(joined, "-D ") {
			t.Fatal(joined)
		}
		if strings.Contains(joined, "sudo ") {
			t.Fatal(joined)
		}
	})
}

func TestFW80ChildDoesNotSudoItself(t *testing.T) {
	restoreExec(t)
	var calls []string
	lookPath = func(name string) (string, error) {
		if name == "iptables" || name == "sudo" {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("missing")
	}
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "sudo" {
			t.Fatal("fw80 子命令不应再 sudo")
		}
		return []byte("Operation not permitted"), errors.New("exit status 4")
	}
	if code := RunFW80([]string{"open", "80"}); code == 0 {
		t.Fatal("没有权限时应失败")
	}
	if strings.Contains(strings.Join(calls, "\n"), "sudo ") {
		t.Fatal(strings.Join(calls, "\n"))
	}
}

func TestSelfExecutableIgnoresSiblingFW80(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "go-tls-proxy")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "fw80")
	if err := os.WriteFile(sibling, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := executablePath
	t.Cleanup(func() { executablePath = old })
	executablePath = func() (string, error) { return exe, nil }
	got, err := selfExecutable()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got == sibling || strings.HasSuffix(got, "/fw80") {
		t.Fatalf("不应指向 fw80 脚本: %s", got)
	}

	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "go-tls-proxy")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return link, nil }
	got, err = selfExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("符号链接解析后 got %q want %q", got, want)
	}

	executablePath = func() (string, error) { return "", errors.New("no exe") }
	if _, err := selfExecutable(); err == nil || strings.Contains(err.Error(), "/data/opt/go-tls-proxy") {
		t.Fatalf("无法取得可执行文件时不应猜安装路径: %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}
