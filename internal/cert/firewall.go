package cert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	execCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		return cmd.CombinedOutput()
	}
	lookPath = exec.LookPath
)

// 只删除带这个注释的规则，管理员自己的放行没有这段注释，不会被删。
const ruleComment = "go-tls-proxy"

// errNoFirewall 表示本机没有 iptables、nft、firewalld、ufw，调用方不能把它当成已经放行。
var errNoFirewall = errors.New("未检测到 iptables、nftables、firewalld 或 ufw")

// errNeedRoot 表示防火墙命令因权限失败。服务进程改用 sudo 执行本程序的 fw80 子命令。
var errNeedRoot = errors.New("需要 root 才能修改防火墙")

// firewallEscalate 为真时，权限不够就 sudo 本程序的 fw80 子命令。
// 子命令进程里会关掉，避免再套一层 sudo。
var firewallEscalate = true

// allowTCP 在申请期间放行入站 TCP。只使用当前生效的一种防火墙。
// undo 只删除本次加上的规则；调用前已经存在的放行不会删。
// kind 写入标记文件，进程被打断后下次启动据此删掉残留规则。
// 当前进程没有权限时，sudo 执行同一个二进制的 fw80 open，不再查找外部脚本。
func allowTCP(ctx context.Context, port int, temporary bool) (undo func(), kind string, err error) {
	if port <= 0 || runtime.GOOS == "windows" {
		return nil, "", nil
	}
	undo, kind, err = allowTCPDirect(ctx, port, temporary)
	if err == nil || !errors.Is(err, errNeedRoot) || !firewallEscalate {
		return undo, kind, err
	}
	slog.Info("当前进程不能改防火墙，改用 sudo 执行 fw80", "port", port)
	return allowTCPViaSudo(ctx, port, temporary)
}

func allowTCPDirect(ctx context.Context, port int, temporary bool) (undo func(), kind string, err error) {
	backend, err := detectBackend(ctx)
	if err != nil {
		return nil, "", err
	}
	switch backend {
	case "firewalld":
		return allowFirewalld(ctx, port, temporary)
	case "ufw":
		return allowUFW(ctx, port, temporary)
	case "nft":
		return allowNFT(ctx, port, temporary)
	case "iptables":
		return allowIptables(ctx, port, temporary)
	default:
		return nil, "", errNoFirewall
	}
}

func detectBackend(ctx context.Context) (string, error) {
	if _, err := lookPath("firewall-cmd"); err == nil {
		out, err := run(ctx, "firewall-cmd", "--state")
		if err == nil {
			return "firewalld", nil
		}
		if !notRunning(out, err) {
			return "", fmt.Errorf("firewalld 已安装，但无法确认状态，未放行端口: %w", err)
		}
	}
	if _, err := lookPath("ufw"); err == nil {
		out, err := run(ctx, "ufw", "status")
		if err == nil && ufwActive(string(out)) {
			return "ufw", nil
		}
		if err != nil && !ufwInactive(out, err) {
			return "", fmt.Errorf("ufw 已安装，但无法确认状态，未放行端口: %w", err)
		}
	}
	_, iptErr := lookPath("iptables")
	_, nftErr := lookPath("nft")
	hasIpt := iptErr == nil
	hasNft := nftErr == nil
	if hasNft {
		out, err := run(ctx, "nft", "list", "ruleset")
		if err != nil {
			if hasIpt {
				return "iptables", nil
			}
			return "", fmt.Errorf("nftables 无法读取，未放行端口: %w", err)
		}
		if nftInputDrop(string(out)) && !iptablesDrop(ctx) {
			return "nft", nil
		}
	}
	if hasIpt {
		return "iptables", nil
	}
	if hasNft {
		return "nft", nil
	}
	return "", errNoFirewall
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := execCommand(ctx, name, args...)
	if err != nil && permissionDenied(out, err) {
		return out, fmt.Errorf("%w: %s", errNeedRoot, clip(out))
	}
	return out, err
}

func permissionDenied(out []byte, err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error() + " " + string(out))
	return strings.Contains(s, "permission denied") ||
		strings.Contains(s, "operation not permitted") ||
		strings.Contains(s, "not authorized") ||
		strings.Contains(s, "you need to be root") ||
		strings.Contains(s, "superuser") ||
		strings.Contains(s, "需要超级用户") ||
		strings.Contains(s, "must be root")
}

func notRunning(out []byte, err error) bool {
	s := strings.ToLower(string(out) + " " + errString(err))
	return strings.Contains(s, "not running") || strings.Contains(s, "inactive")
}

func ufwInactive(out []byte, err error) bool {
	s := strings.ToLower(string(out) + " " + errString(err))
	return strings.Contains(s, "inactive") || strings.Contains(s, "status: inactive")
}

func ufwActive(out string) bool {
	return strings.Contains(strings.ToLower(out), "status: active")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func clip(out []byte) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "无输出"
	}
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

func sweepPort80(ctx context.Context, dir string) {
	if strings.TrimSpace(dir) == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, "port80.open"))
	if err != nil {
		return
	}
	closeMarked(ctx, strings.TrimSpace(string(raw)))
	_ = os.Remove(filepath.Join(dir, "port80.open"))
}

func closeMarked(ctx context.Context, mark string) {
	err := closeMarkedDirect(ctx, mark)
	if err == nil || !errors.Is(err, errNeedRoot) || !firewallEscalate {
		return
	}
	closeViaSudo(ctx, mark)
}

func closeMarkedDirect(ctx context.Context, mark string) error {
	fields := strings.Fields(mark)
	if len(fields) == 0 {
		return nil
	}
	port := 80
	if n, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
		port = n
		fields = fields[:len(fields)-1]
	}
	if len(fields) == 0 {
		return nil
	}
	switch fields[0] {
	case "iptables":
		_, err := run(ctx, "iptables", append([]string{"-D", "INPUT"}, iptablesMatch(port)...)...)
		if errors.Is(err, errNeedRoot) {
			return err
		}
	case "firewalld":
		spec := strconv.Itoa(port) + "/tcp"
		if _, err := run(ctx, "firewall-cmd", "--remove-port="+spec); errors.Is(err, errNeedRoot) {
			return err
		}
		// 运行时规则和写进永久配置的规则都删，崩溃重启后 80 不会留下。
		if _, err := run(ctx, "firewall-cmd", "--permanent", "--remove-port="+spec); errors.Is(err, errNeedRoot) {
			return err
		}
	case "ufw":
		if err := ufwDeleteOurs(ctx, port); errors.Is(err, errNeedRoot) {
			return err
		}
	case "nft":
		if len(fields) >= 4 {
			if err := nftDeleteOurs(ctx, fields[1], fields[2], fields[3]); errors.Is(err, errNeedRoot) {
				return err
			}
		}
	}
	return nil
}

func iptablesMatch(port int) []string {
	return []string{"-p", "tcp", "--dport", strconv.Itoa(port), "-m", "comment", "--comment", ruleComment, "-j", "ACCEPT"}
}

func iptablesDrop(ctx context.Context) bool {
	if _, err := lookPath("iptables"); err != nil {
		return false
	}
	out, err := run(ctx, "iptables", "-S", "INPUT")
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "-P INPUT DROP") || strings.Contains(s, "-P INPUT REJECT")
}

func allowIptables(ctx context.Context, port int, temporary bool) (func(), string, error) {
	match := iptablesMatch(port)
	if _, err := run(ctx, "iptables", append([]string{"-C", "INPUT"}, match...)...); err == nil {
		return nil, "", nil
	} else if errors.Is(err, errNeedRoot) {
		return nil, "", err
	}
	insert := append([]string{"-I", "INPUT", "1"}, match...)
	out, err := run(ctx, "iptables", insert...)
	if err != nil {
		return nil, "", fmt.Errorf("iptables 未能放行 %d/tcp: %w", port, err)
	}
	if strings.TrimSpace(string(out)) != "" && permissionDenied(out, errors.New(string(out))) {
		return nil, "", fmt.Errorf("iptables 未能放行 %d/tcp: %w", port, errNeedRoot)
	}
	kind := fmt.Sprintf("iptables %d", port)
	if !temporary {
		return nil, kind, nil
	}
	return func() {
		_, _ = run(context.Background(), "iptables", append([]string{"-D", "INPUT"}, match...)...)
	}, kind, nil
}

func allowFirewalld(ctx context.Context, port int, temporary bool) (func(), string, error) {
	spec := strconv.Itoa(port) + "/tcp"
	if _, err := run(ctx, "firewall-cmd", "--query-port="+spec); err == nil {
		return nil, "", nil
	} else if errors.Is(err, errNeedRoot) {
		return nil, "", err
	}
	if out, err := run(ctx, "firewall-cmd", "--add-port="+spec); err != nil {
		return nil, "", fmt.Errorf("firewalld 未能放行 %s: %w", spec, err)
	} else if !portAdded(string(out)) && strings.TrimSpace(string(out)) != "" && !strings.Contains(strings.ToLower(string(out)), "success") {
		return nil, "", fmt.Errorf("firewalld 未能放行 %s: %s", spec, clip(out))
	}
	kind := fmt.Sprintf("firewalld %d", port)
	if !temporary {
		return nil, kind, nil
	}
	return func() {
		_, _ = run(context.Background(), "firewall-cmd", "--remove-port="+spec)
	}, kind, nil
}

func portAdded(out string) bool {
	s := strings.ToLower(strings.TrimSpace(out))
	return s == "" || s == "success" || strings.Contains(s, "success")
}

type ufwRule struct {
	num  int
	to   string
	ours bool
}

var ufwLineRE = regexp.MustCompile(`^\[\s*(\d+)\]\s+(\S+)\s+(ALLOW\S*)`)

func parseUFW(out string) []ufwRule {
	var rules []ufwRule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		m := ufwLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		rules = append(rules, ufwRule{num: n, to: m[2], ours: strings.Contains(line, ruleComment)})
	}
	return rules
}

func ufwPort(to string, port int) bool {
	p := strconv.Itoa(port)
	return to == p || to == p+"/tcp" || strings.HasPrefix(to, p+"/")
}

func allowUFW(ctx context.Context, port int, temporary bool) (func(), string, error) {
	out, err := run(ctx, "ufw", "status", "numbered")
	if err != nil {
		return nil, "", fmt.Errorf("ufw 未能读取状态，未放行 %d/tcp: %w", port, err)
	}
	for _, rule := range parseUFW(string(out)) {
		if ufwPort(rule.to, port) {
			return nil, "", nil
		}
	}
	if out, err = run(ctx, "ufw", "--force", "allow", strconv.Itoa(port)+"/tcp", "comment", ruleComment); err != nil {
		return nil, "", fmt.Errorf("ufw 未能放行 %d/tcp: %w", port, err)
	}
	kind := fmt.Sprintf("ufw %d", port)
	if !temporary {
		return nil, kind, nil
	}
	return func() { _ = ufwDeleteOurs(context.Background(), port) }, kind, nil
}

// cleanupHostFirewall 在服务启动和 -issue 开始时调用。
// 先按 port80.open 删崩溃留下的规则（含 ufw / firewalld 永久配置），再删带本项目注释的旧长期规则。
func cleanupHostFirewall(ctx context.Context, dir string) {
	sweepPort80(ctx, dir)
	purgeOurRules(ctx)
	cleanupNoteOnce.Do(func() {
		slog.Info("云厂商安全组需要在控制台放行 TCP 80，程序不能修改安全组")
		noteUntaggedFirewalld(ctx)
	})
}

var cleanupNoteOnce sync.Once

func noteUntaggedFirewalld(ctx context.Context) {
	if _, err := lookPath("firewall-cmd"); err != nil {
		return
	}
	if _, err := run(ctx, "firewall-cmd", "--state"); err != nil {
		return
	}
	out, err := run(ctx, "firewall-cmd", "--query-port=80/tcp")
	if err != nil || strings.EqualFold(strings.TrimSpace(string(out)), "no") {
		return
	}
	slog.Warn("firewalld 已放行 80/tcp，但这条规则没有 " + ruleComment + " 注释，无法判断是不是本程序加的，本次不删除。确认后可在服务器执行 firewall-cmd --remove-port=80/tcp 和 firewall-cmd --permanent --remove-port=80/tcp")
}

func purgeOurRules(ctx context.Context) {
	for _, backend := range []string{"iptables", "ufw", "nft"} {
		err := purgeBackend(ctx, backend)
		if err == nil || !errors.Is(err, errNeedRoot) || !firewallEscalate {
			continue
		}
		slog.Info("当前进程不能删除旧的防火墙规则，改用 sudo 执行 fw80", "firewall", backend)
		if _, sudoErr := sudoFW80(ctx, "close", "purge", backend); sudoErr != nil {
			slog.Error("删除旧的放行失败", "firewall", backend, "err", sudoErr)
		}
	}
}

func purgeSelected(ctx context.Context, which []string) error {
	backends := which
	if len(backends) == 0 {
		backends = []string{"iptables", "ufw", "nft"}
	}
	for _, backend := range backends {
		if err := purgeBackend(ctx, backend); err != nil {
			return err
		}
	}
	return nil
}

func purgeBackend(ctx context.Context, backend string) error {
	switch backend {
	case "iptables":
		return purgeIptables(ctx)
	case "ufw":
		return purgeUFW(ctx)
	case "nft":
		return purgeNFT(ctx)
	default:
		return nil
	}
}

func purgeIptables(ctx context.Context) error {
	if _, err := lookPath("iptables"); err != nil {
		return nil
	}
	out, err := run(ctx, "iptables", "-S", "INPUT")
	if errors.Is(err, errNeedRoot) {
		return err
	}
	if err != nil {
		slog.Error("读取 iptables 失败，带 "+ruleComment+" 注释的规则可能还在", "err", err)
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "--comment "+ruleComment) || !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		fields[0] = "-D"
		if _, err := run(ctx, "iptables", fields...); err != nil {
			if errors.Is(err, errNeedRoot) {
				return err
			}
			slog.Error("删除旧的 iptables 放行失败", "rule", line, "err", err)
			continue
		}
		slog.Info("已删除旧的长期放行", "firewall", "iptables", "rule", line)
	}
	return nil
}

func purgeUFW(ctx context.Context) error {
	if _, err := lookPath("ufw"); err != nil {
		return nil
	}
	if err := ufwDeleteOurs(ctx, 0); err != nil {
		if errors.Is(err, errNeedRoot) {
			return err
		}
		slog.Error("删除旧的 ufw 放行失败", "err", err)
	}
	return nil
}

func purgeNFT(ctx context.Context) error {
	if _, err := lookPath("nft"); err != nil {
		return nil
	}
	out, err := run(ctx, "nft", "list", "ruleset")
	if errors.Is(err, errNeedRoot) {
		return err
	}
	if err != nil {
		slog.Error("读取 nftables 失败，带 "+ruleComment+" 注释的规则可能还在", "err", err)
		return nil
	}
	seen := map[string]struct{}{}
	for _, chain := range parseNFT(string(out)) {
		if !chain.ours {
			continue
		}
		key := chain.family + " " + chain.table + " " + chain.name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if err := nftDeleteOurs(ctx, chain.family, chain.table, chain.name); err != nil {
			if errors.Is(err, errNeedRoot) {
				return err
			}
			slog.Error("删除旧的 nft 放行失败", "chain", key, "err", err)
			continue
		}
		slog.Info("已删除旧的长期放行", "firewall", "nft", "chain", key)
	}
	return nil
}

func ufwDeleteOurs(ctx context.Context, port int) error {
	out, err := run(ctx, "ufw", "status", "numbered")
	if err != nil {
		return err
	}
	var nums []int
	for _, rule := range parseUFW(string(out)) {
		if !rule.ours {
			continue
		}
		if port > 0 && !ufwPort(rule.to, port) {
			continue
		}
		nums = append(nums, rule.num)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	for _, n := range nums {
		if _, err = run(ctx, "ufw", "--force", "delete", strconv.Itoa(n)); err != nil {
			return err
		}
	}
	return nil
}

type nftChain struct {
	family string
	table  string
	name   string
	drop   bool
	ours   bool
}

func parseNFT(ruleset string) []nftChain {
	var chains []nftChain
	var family, table, chain string
	inChain := false
	var body strings.Builder
	for _, line := range strings.Split(ruleset, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "table ") {
			fields := strings.Fields(trim)
			if len(fields) >= 3 {
				family, table = fields[1], strings.TrimSuffix(fields[2], "{")
			}
			continue
		}
		if strings.HasPrefix(trim, "chain ") && strings.Contains(trim, "{") {
			fields := strings.Fields(trim)
			if len(fields) >= 2 {
				chain = strings.TrimSuffix(fields[1], "{")
				inChain = true
				body.Reset()
			}
			continue
		}
		if inChain && trim == "}" {
			text := body.String()
			if strings.Contains(text, "hook input") {
				chains = append(chains, nftChain{
					family: family,
					table:  table,
					name:   chain,
					drop:   strings.Contains(text, "policy drop"),
					ours:   strings.Contains(text, ruleComment),
				})
			}
			inChain = false
			continue
		}
		if inChain {
			body.WriteString(trim)
			body.WriteByte('\n')
		}
	}
	return chains
}

func nftInputDrop(ruleset string) bool {
	for _, chain := range parseNFT(ruleset) {
		if chain.drop {
			return true
		}
	}
	return false
}

func pickNFTChain(ruleset string) (nftChain, bool) {
	chains := parseNFT(ruleset)
	for _, chain := range chains {
		if chain.drop {
			return chain, true
		}
	}
	if len(chains) > 0 {
		return chains[0], true
	}
	return nftChain{}, false
}

var nftHandleRE = regexp.MustCompile(`comment "` + ruleComment + `".*handle (\d+)`)

func nftHandles(out string) []string {
	var handles []string
	for _, line := range strings.Split(out, "\n") {
		if m := nftHandleRE.FindStringSubmatch(line); m != nil {
			handles = append(handles, m[1])
		}
	}
	return handles
}

func allowNFT(ctx context.Context, port int, temporary bool) (func(), string, error) {
	out, err := run(ctx, "nft", "list", "ruleset")
	if err != nil {
		return nil, "", fmt.Errorf("nftables 未能读取规则，未放行 %d/tcp: %w", port, err)
	}
	chain, ok := pickNFTChain(string(out))
	if !ok {
		return nil, "", fmt.Errorf("nftables 没有 input 链，未放行 %d/tcp", port)
	}
	if strings.Contains(string(out), ruleComment) {
		return nil, "", nil
	}
	if out, err = run(ctx, "nft", "insert", "rule", chain.family, chain.table, chain.name,
		"tcp", "dport", strconv.Itoa(port), "accept", "comment", `"`+ruleComment+`"`); err != nil {
		return nil, "", fmt.Errorf("nftables 未能放行 %d/tcp: %w", port, err)
	}
	kind := fmt.Sprintf("nft %s %s %s %d", chain.family, chain.table, chain.name, port)
	if !temporary {
		return nil, kind, nil
	}
	family, table, name := chain.family, chain.table, chain.name
	return func() { _ = nftDeleteOurs(context.Background(), family, table, name) }, kind, nil
}

func nftDeleteOurs(ctx context.Context, family, table, chain string) error {
	out, err := run(ctx, "nft", "-a", "list", "chain", family, table, chain)
	if err != nil {
		return err
	}
	handles := nftHandles(string(out))
	sort.Sort(sort.Reverse(sort.StringSlice(handles)))
	for _, handle := range handles {
		if _, err := run(ctx, "nft", "delete", "rule", family, table, chain, "handle", handle); err != nil {
			return err
		}
	}
	return nil
}
