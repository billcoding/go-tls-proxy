package cert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// nginx 已经在 80 端口提供校验文件时，写到这个目录，不再绑定端口。
var knownChallengeDirs = []string{
	"/var/www/go-tls-proxy/.well-known/acme-challenge",
}

var (
	nginxRunning = detectNginx
	listenTCP    = net.Listen
)

func (m *Manager) openHTTP01(ctx context.Context) (func(), error) {
	if m.challenge != "http-01" {
		return func() {}, nil
	}
	port := m.httpPort
	if port == 0 {
		port = 80
	}
	sweepPort80(ctx, m.storage)
	if root, ok := challengeDir(m.webRoot); ok {
		return m.useWebRoot(ctx, root, port)
	}
	undo := allowPort(ctx, m.storage, port)
	addr := fmt.Sprintf(":%d", port)
	ln, err := listenTCP("tcp", addr)
	if err != nil && isAddrInUse(err) && strings.TrimSpace(m.webRoot) != "" {
		if mkErr := os.MkdirAll(m.webRoot, 0o755); mkErr != nil {
			abandonPort(m.storage, undo)
			return nil, fmt.Errorf("监听 %s 失败: %w", addr, err)
		}
		m.http01.setWebRoot(m.webRoot)
		slog.Info("端口被占用，http-01 改写校验目录", "addr", addr, "webroot", m.webRoot)
		return func() { abandonPort(m.storage, undo) }, nil
	}
	if err != nil {
		abandonPort(m.storage, undo)
		return nil, fmt.Errorf("监听 %s 失败（申请期间 80 端口需要空闲；若 nginx 已在提供校验文件，请使用已有的 ACME 目录）: %w", addr, err)
	}
	srv := &http.Server{
		Handler:           m.http01,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	slog.Info("已临时打开端口用于 http-01，校验结束后关闭", "addr", addr)
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
		abandonPort(m.storage, undo)
		slog.Info("已关闭 http-01 端口", "addr", addr)
	}, nil
}

func (m *Manager) useWebRoot(ctx context.Context, root string, port int) (func(), error) {
	undo := allowPort(ctx, m.storage, port)
	if err := os.MkdirAll(root, 0o755); err != nil {
		abandonPort(m.storage, undo)
		return nil, fmt.Errorf("创建 ACME 校验目录失败: %w", err)
	}
	m.http01.setWebRoot(root)
	slog.Info("http-01 写入已有站点目录，不占用端口", "webroot", root)
	return func() { abandonPort(m.storage, undo) }, nil
}

func challengeDir(configured string) (string, bool) {
	if nginxRunning == nil || !nginxRunning() {
		return "", false
	}
	if p := strings.TrimSpace(configured); dirExists(p) {
		return p, true
	}
	for _, p := range knownChallengeDirs {
		if dirExists(p) {
			return p, true
		}
	}
	return "", false
}

func dirExists(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func allowPort(ctx context.Context, dir string, port int) func() {
	undo, kind, err := allowTCP(ctx, port, true)
	if err != nil {
		if errors.Is(err, errNoFirewall) {
			slog.Warn("没有检测到防火墙，未放行端口。若另有防火墙拦截，HTTP-01 会失败", "port", port)
		} else {
			slog.Error("未能临时放行端口，HTTP-01 可能失败", "port", port, "err", err)
		}
		return func() {}
	}
	if kind == "" {
		slog.Info("端口已有放行，本次不添加，结束时也不删除", "port", port)
		return func() {}
	}
	if dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "port80.open"), []byte(kind+"\n"), 0o600)
	}
	slog.Info("已临时放行入站 TCP，校验结束后删除", "port", port, "rule", kind)
	return undo
}

func abandonPort(dir string, undo func()) {
	if undo != nil {
		undo()
		slog.Info("已收回本次 http-01 端口放行")
	}
	if dir != "" {
		_ = os.Remove(filepath.Join(dir, "port80.open"))
	}
}

func detectNginx() bool {
	if scanProcComm("nginx") {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := lookPath("pgrep"); err != nil {
		return false
	}
	out, err := execCommand(ctx, "pgrep", "-x", "nginx")
	return err == nil && strings.TrimSpace(string(out)) != ""
}

func scanProcComm(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == name {
			return true
		}
	}
	return false
}

func isAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already in use") ||
		strings.Contains(s, "only one usage of each socket address")
}
