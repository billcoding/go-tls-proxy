package cert

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAllowTCPInsertsAndDeletes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
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
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo == nil || kind != "iptables 80" {
		t.Fatalf("undo %v kind %s", undo != nil, kind)
	}
	undo()
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "-I INPUT 1 -p tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT") ||
		!strings.Contains(joined, "-D INPUT -p tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "sudo ") || strings.Contains(joined, "fw80") {
		t.Fatal(joined)
	}
}

func TestAllowTCPKeepsExistingRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	restoreExec(t)
	var calls []string
	lookPath = only("iptables")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo != nil || kind != "" {
		t.Fatalf("已有规则应保留，undo %v kind %q", undo != nil, kind)
	}
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, "-I ") || strings.Contains(joined, "-D ") {
		t.Fatal(joined)
	}
}

func TestAllowTCPPrefersFirewalld(t *testing.T) {
	restoreExec(t)
	var calls []string
	lookPath = func(name string) (string, error) {
		if name == "firewall-cmd" || name == "iptables" {
			return "/usr/sbin/" + name, nil
		}
		return "", errors.New("missing")
	}
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "firewall-cmd" && len(args) > 0 && args[0] == "--state" {
			return []byte("running\n"), nil
		}
		if name == "firewall-cmd" && strings.Contains(strings.Join(args, " "), "--query-port") {
			return nil, errors.New("no")
		}
		return []byte("success\n"), nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo == nil || kind != "firewalld 80" {
		t.Fatalf("undo %v kind %s", undo != nil, kind)
	}
	undo()
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, "iptables ") || strings.Contains(joined, "--permanent") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "--add-port=80/tcp") || !strings.Contains(joined, "--remove-port=80/tcp") {
		t.Fatal(joined)
	}
}

func TestFirewalldLeavesExistingPort(t *testing.T) {
	restoreExec(t)
	var calls []string
	lookPath = only("firewall-cmd")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if strings.Contains(strings.Join(args, " "), "--state") {
			return []byte("running\n"), nil
		}
		return nil, nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo != nil || kind != "" {
		t.Fatalf("已有 firewalld 放行不应删除，undo %v kind %q", undo != nil, kind)
	}
	if strings.Contains(strings.Join(calls, "\n"), "--remove-port") || strings.Contains(strings.Join(calls, "\n"), "--add-port") {
		t.Fatal(strings.Join(calls, "\n"))
	}
}

func TestAllowUFWAddsAndDeletesOnlyOurs(t *testing.T) {
	restoreExec(t)
	var calls []string
	added := false
	lookPath = only("ufw")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name != "ufw" {
			return nil, errors.New("unexpected")
		}
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
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo == nil || kind != "ufw 80" {
		t.Fatalf("undo %v kind %s", undo != nil, kind)
	}
	undo()
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "ufw --force allow 80/tcp comment go-tls-proxy") ||
		!strings.Contains(joined, "ufw --force delete 2") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "delete 1") {
		t.Fatal(joined)
	}
}

func TestUFWKeepsAdminPort(t *testing.T) {
	restoreExec(t)
	var calls []string
	lookPath = only("ufw")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) == 1 {
			return []byte("Status: active\n"), nil
		}
		return []byte("Status: active\n[ 1] 80/tcp ALLOW IN Anywhere\n"), nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo != nil || kind != "" {
		t.Fatalf("管理员的 80 放行应保留，undo %v kind %q", undo != nil, kind)
	}
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, " allow ") || strings.Contains(joined, "delete") {
		t.Fatal(joined)
	}
}

func TestAllowNFTInsertsAndDeletesOnlyOurs(t *testing.T) {
	restoreExec(t)
	var calls []string
	lookPath = func(name string) (string, error) {
		if name == "nft" || name == "iptables" {
			return "/usr/sbin/" + name, nil
		}
		return "", errors.New("missing")
	}
	ruleset := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"
	listed := "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept # handle 2\n\t\ttcp dport 80 accept comment \"go-tls-proxy\" # handle 9\n\t}\n}\n"
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "iptables" {
			return []byte("-P INPUT ACCEPT\n"), nil
		}
		if name == "nft" && len(args) >= 2 && args[0] == "list" {
			return []byte(ruleset), nil
		}
		if name == "nft" && len(args) >= 2 && args[0] == "-a" {
			return []byte(listed), nil
		}
		return nil, nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo == nil || kind != "nft inet filter input 80" {
		t.Fatalf("undo %v kind %s err %v", undo != nil, kind, err)
	}
	undo()
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "nft insert rule inet filter input tcp dport 80 accept comment \"go-tls-proxy\"") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "nft delete rule inet filter input handle 9") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "handle 2") && strings.Contains(joined, "delete rule") && strings.Contains(joined, "handle 2") {
		t.Fatal(joined)
	}
}

func TestNoFirewallIsAnError(t *testing.T) {
	restoreExec(t)
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	execCommand = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("没有防火墙时不应执行命令")
		return nil, nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if !errors.Is(err, errNoFirewall) || undo != nil || kind != "" {
		t.Fatalf("undo %v kind %q err %v", undo != nil, kind, err)
	}
}

func TestFirewallPermissionIsReported(t *testing.T) {
	restoreExec(t)
	lookPath = only("iptables")
	execCommand = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-C" {
			return nil, errors.New("No chain/target/match")
		}
		return []byte("Permission denied"), errors.New("exit status 4")
	}
	undo, _, err := allowTCP(context.Background(), 80, true)
	if err == nil || !strings.Contains(err.Error(), "没有权限") {
		t.Fatal(err)
	}
	if undo != nil {
		t.Fatal("失败时不应留下回收函数")
	}
}

func TestSudoUsesBinarySubcommand(t *testing.T) {
	restoreExec(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "go-tls-proxy")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "fw80")
	if err := os.WriteFile(sibling, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
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
			if len(args) >= 4 && args[3] == "open" {
				return []byte("iptables 80\n"), nil
			}
			return nil, nil
		}
		if len(args) > 0 && args[0] == "-I" {
			return []byte("Operation not permitted"), errors.New("exit status 4")
		}
		if len(args) > 0 && args[0] == "-C" {
			return nil, errors.New("missing")
		}
		return nil, nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo == nil || kind != "iptables 80" {
		t.Fatalf("undo %v kind %s", undo != nil, kind)
	}
	undo()
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	wantOpen := "sudo -n " + resolved + " fw80 open 80"
	wantClose := "sudo -n " + resolved + " fw80 close iptables 80"
	if !strings.Contains(joined, wantOpen) || !strings.Contains(joined, wantClose) {
		t.Fatal(joined)
	}
	if strings.Contains(joined, sibling) || strings.Contains(joined, "sudo -n iptables") {
		t.Fatal(joined)
	}
}

func TestDirectPathIgnoresSiblingFW80(t *testing.T) {
	restoreExec(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "go-tls-proxy")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "fw80")
	if err := os.WriteFile(sibling, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return exe, nil }
	var calls []string
	lookPath = only("iptables")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) > 0 && args[0] == "-C" {
			return nil, errors.New("missing")
		}
		return nil, nil
	}
	undo, kind, err := allowTCP(context.Background(), 80, true)
	if err != nil {
		t.Fatal(err)
	}
	if undo == nil || kind != "iptables 80" {
		t.Fatalf("undo %v kind %s", undo != nil, kind)
	}
	undo()
	joined := strings.Join(calls, "\n")
	if strings.Contains(joined, sibling) || strings.Contains(joined, "sudo ") || strings.Contains(joined, " fw80") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "iptables -I INPUT 1") || !strings.Contains(joined, "iptables -D INPUT") {
		t.Fatal(joined)
	}
}

func TestPurgeEscalatesToSubcommand(t *testing.T) {
	restoreExec(t)
	exe := "/opt/go-tls-proxy/go-tls-proxy"
	executablePath = func() (string, error) { return exe, nil }
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
			return nil, nil
		}
		return []byte("Operation not permitted"), errors.New("exit status 4")
	}
	purgeOurRules(context.Background())
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "sudo -n "+exe+" fw80 close purge iptables") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "/opt/go-tls-proxy/fw80") || strings.Contains(joined, "sudo -n iptables") {
		t.Fatal(joined)
	}
}

func TestPurgeDeletesOnlyCommentedIptables(t *testing.T) {
	restoreExec(t)
	lookPath = only("iptables")
	var calls []string
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) >= 1 && args[0] == "-S" {
			return []byte("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT\n"), nil
		}
		return nil, nil
	}
	purgeIptables(context.Background())
	got := strings.Join(calls, "\n")
	if !strings.Contains(got, "-D INPUT -p tcp -m tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT") {
		t.Fatal(got)
	}
	if strings.Contains(got, "--dport 22") {
		t.Fatal(got)
	}
}

func TestCloseMarkedFirewalldRemovesPermanent(t *testing.T) {
	restoreExec(t)
	var calls []string
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return []byte("success\n"), nil
	}
	closeMarked(context.Background(), "firewalld 80")
	got := strings.Join(calls, "\n")
	if !strings.Contains(got, "firewall-cmd --remove-port=80/tcp") || !strings.Contains(got, "firewall-cmd --permanent --remove-port=80/tcp") {
		t.Fatal(got)
	}
	if strings.Contains(got, "--add-port") {
		t.Fatal(got)
	}
}

func TestSweepRemovesMarkedRule(t *testing.T) {
	restoreExec(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "port80.open"), []byte("iptables 80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	lookPath = only("iptables")
	execCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	sweepPort80(context.Background(), dir)
	if _, err := os.Stat(filepath.Join(dir, "port80.open")); !os.IsNotExist(err) {
		t.Fatal("标记文件还在")
	}
	if !strings.Contains(strings.Join(calls, "\n"), "-D INPUT -p tcp --dport 80 -m comment --comment go-tls-proxy -j ACCEPT") {
		t.Fatal(strings.Join(calls, "\n"))
	}
}

func restoreExec(t *testing.T) {
	t.Helper()
	oldExec, oldLook := execCommand, lookPath
	oldExe := executablePath
	oldEscalate := firewallEscalate
	firewallEscalate = true
	executablePath = func() (string, error) {
		return filepath.Join(t.TempDir(), "go-tls-proxy"), nil
	}
	t.Cleanup(func() {
		execCommand = oldExec
		lookPath = oldLook
		executablePath = oldExe
		firewallEscalate = oldEscalate
	})
}

func only(names ...string) func(string) (string, error) {
	ok := map[string]struct{}{}
	for _, name := range names {
		ok[name] = struct{}{}
	}
	return func(name string) (string, error) {
		if _, found := ok[name]; found {
			return "/usr/sbin/" + name, nil
		}
		return "", errors.New("missing")
	}
}
