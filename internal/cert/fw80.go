package cert

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// executablePath 返回当前进程的可执行文件。测试可替换。
var executablePath = os.Executable

// RunFW80 执行防火墙子命令。
// open 临时放行一个 TCP 端口，close 收回本次放行，或清掉带本项目注释的残留规则。
// 参数不合法时直接拒绝，不调用防火墙命令。
func RunFW80(args []string) int {
	prev := firewallEscalate
	firewallEscalate = false
	defer func() { firewallEscalate = prev }()

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "fw80: 用法: go-tls-proxy fw80 open <端口> | go-tls-proxy fw80 close <标记>\n")
		return 1
	}
	switch args[0] {
	case "open":
		return fw80Open(args[1:])
	case "close":
		return fw80Close(args[1:])
	default:
		return fw80Reject(args)
	}
}

func fw80Open(args []string) int {
	if len(args) != 1 || !validPort(args[0]) {
		return fw80Reject(append([]string{"open"}, args...))
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		return fw80Reject(append([]string{"open"}, args...))
	}
	_, kind, err := allowTCP(context.Background(), port, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fw80: %s\n", err)
		return 1
	}
	if kind != "" {
		fmt.Println(kind)
	}
	return 0
}

func fw80Close(args []string) int {
	if len(args) > 0 && args[0] == "purge" {
		if !purgeArgsOK(args[1:]) {
			return fw80Reject(append([]string{"close"}, args...))
		}
		if err := purgeSelected(context.Background(), args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "fw80: %s\n", err)
			return 1
		}
		return 0
	}
	if !closeArgsOK(args) {
		return fw80Reject(append([]string{"close"}, args...))
	}
	if err := closeMarkedDirect(context.Background(), strings.Join(args, " ")); err != nil {
		fmt.Fprintf(os.Stderr, "fw80: %s\n", err)
		return 1
	}
	return 0
}

func fw80Reject(args []string) int {
	msg := strings.Join(args, " ")
	if len(msg) > 120 {
		msg = msg[:120]
	}
	fmt.Fprintf(os.Stderr, "fw80: 拒绝 %s\n", msg)
	return 1
}

var (
	portSpecRE = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func validPort(s string) bool {
	if !portSpecRE.MatchString(s) {
		return false
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

func validName(s string) bool {
	return nameRE.MatchString(s) && len(s) <= 64
}

func closeArgsOK(args []string) bool {
	switch {
	case len(args) == 2 && (args[0] == "iptables" || args[0] == "firewalld" || args[0] == "ufw") && validPort(args[1]):
		return true
	case len(args) == 5 && args[0] == "nft" && validName(args[1]) && validName(args[2]) && validName(args[3]) && validPort(args[4]):
		return true
	default:
		return false
	}
}

func purgeArgsOK(args []string) bool {
	if len(args) == 0 {
		return true
	}
	if len(args) != 1 {
		return false
	}
	switch args[0] {
	case "iptables", "ufw", "nft":
		return true
	default:
		return false
	}
}

func selfExecutable() (string, error) {
	exe, err := executablePath()
	if err != nil {
		return "", err
	}
	exe = strings.TrimSpace(exe)
	if exe == "" {
		return "", fmt.Errorf("可执行文件路径为空")
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	if !filepath.IsAbs(exe) {
		abs, err := filepath.Abs(exe)
		if err != nil {
			return "", err
		}
		exe = abs
	}
	return exe, nil
}

func sudoFW80(ctx context.Context, args ...string) ([]byte, error) {
	if _, err := lookPath("sudo"); err != nil {
		return nil, fmt.Errorf("没有权限修改防火墙（需要 root、CAP_NET_ADMIN，或在 sudoers 中允许本程序执行 fw80 open / fw80 close）")
	}
	exe, err := selfExecutable()
	if err != nil {
		return nil, fmt.Errorf("没有权限修改防火墙，无法确定本程序路径: %w", err)
	}
	full := append([]string{"-n", exe, "fw80"}, args...)
	out, err := execCommand(ctx, "sudo", full...)
	if err != nil {
		return out, fmt.Errorf("没有权限修改防火墙，sudo fw80 %s 失败: %s", strings.Join(args, " "), clip(out))
	}
	return out, nil
}

func allowTCPViaSudo(ctx context.Context, port int, temporary bool) (func(), string, error) {
	out, err := sudoFW80(ctx, "open", strconv.Itoa(port))
	if err != nil {
		return nil, "", err
	}
	kind := strings.TrimSpace(string(out))
	if kind == "" {
		return nil, "", nil
	}
	if strings.ContainsAny(kind, "\r\n") || !strings.HasSuffix(kind, " "+strconv.Itoa(port)) || !closeArgsOK(strings.Fields(kind)) {
		return nil, "", fmt.Errorf("fw80 open 返回了无法识别的规则标记")
	}
	if !temporary {
		return nil, kind, nil
	}
	return func() { closeViaSudo(context.Background(), kind) }, kind, nil
}

func closeViaSudo(ctx context.Context, mark string) {
	fields := strings.Fields(mark)
	if !closeArgsOK(fields) {
		return
	}
	if _, err := sudoFW80(ctx, append([]string{"close"}, fields...)...); err != nil {
		slog.Error("收回防火墙放行失败", "rule", mark, "err", err)
	}
}
