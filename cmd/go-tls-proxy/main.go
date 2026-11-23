package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/billcoding/go-tls-proxy/internal/cert"
	"github.com/billcoding/go-tls-proxy/internal/config"
	"github.com/billcoding/go-tls-proxy/internal/proxy"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "fw80" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
		os.Exit(cert.RunFW80(os.Args[2:]))
	}
	os.Exit(run())
}

func run() int {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	configPath := flag.String("config", "", "配置文件路径（默认 config/go-tls-proxy.yml）")
	issueOnce := flag.Bool("issue", false, "申请或续期 IP 证书后退出，不启动代理")
	dryRun := flag.Bool("dry-run", false, "只检查配置和证书路径，不连接证书机构")
	flag.Parse()

	cfg, err := config.Load(resolveConfigPath(*configPath))
	if err != nil {
		slog.Error("读取配置失败", "err", err)
		return 1
	}
	if *dryRun {
		resolveCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		ips, ipErr := cert.ResolveIPs(resolveCtx, cfg.Certificate.IPs)
		cancel()
		printDryRun(cfg, ips, ipErr)
		return 0
	}

	resolveCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	ips, err := cert.ResolveIPs(resolveCtx, cfg.Certificate.IPs)
	cancel()
	if err != nil {
		slog.Error("解析证书 IP 失败", "err", err)
		return 1
	}
	slog.Info("证书 IP", "ips", formatIPs(ips))

	manager := cert.NewManager(cert.Options{
		Email:      cfg.Certificate.Email,
		IPs:        ips,
		StorageDir: cfg.Certificate.StorageDir,
		Directory:  cfg.Certificate.Directory,
		Profile:    cfg.Certificate.Profile,
		Challenge:  cfg.Certificate.Challenge,
		HTTPPort:   cfg.Certificate.HTTPPort,
		RenewEvery: cfg.Certificate.RenewInterval,
		Staging:    cfg.Certificate.Staging,
	})
	if *issueOnce {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := manager.Ensure(ctx); err != nil {
			slog.Error("申请证书失败", "err", err)
			return 1
		}
		slog.Info("证书已写入",
			"cert", filepath.Join(cfg.Certificate.StorageDir, "cert.pem"),
			"key", filepath.Join(cfg.Certificate.StorageDir, "key.pem"),
		)
		return 0
	}
	if err := manager.Prepare(); err != nil {
		slog.Error("准备证书失败", "err", err)
		return 1
	}

	server, err := proxy.New(cfg.Proxies, manager.TLSConfig(), proxy.Options{
		EnableACME: true,
		Challenge:  cfg.Certificate.Challenge,
		Docker:     cfg.Docker,
	})
	if err != nil {
		slog.Error("启动代理失败", "err", err)
		return 1
	}
	server.Start()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()

	select {
	case <-ctx.Done():
		slog.Info("正在停止")
	case err := <-errCh:
		if err != nil {
			slog.Error("证书管理停止", "err", err)
			shutdown(server)
			return 1
		}
	}
	shutdown(server)
	return 0
}

func shutdown(server *proxy.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("停止代理时出现错误", "err", err)
	}
}

func printDryRun(cfg *config.File, ips []net.IP, ipErr error) {
	dir := cfg.Certificate.StorageDir
	slog.Info("dry-run：不连接证书机构，不写入证书")
	slog.Info("证书配置",
		"challenge", cfg.Certificate.Challenge,
		"profile", cfg.Certificate.Profile,
		"directory", cert.DirectoryFor(cfg.Certificate.Directory, cfg.Certificate.Staging),
		"storage", dir,
		"http_port", cfg.Certificate.HTTPPort,
		"renew_every", cfg.Certificate.RenewInterval.String(),
	)
	slog.Info("证书文件",
		"cert", filepath.Join(dir, "cert.pem"),
		"key", filepath.Join(dir, "key.pem"),
		"account", filepath.Join(dir, "account.key"),
		"email", filepath.Join(dir, "account.email"),
	)
	if ipErr != nil {
		slog.Warn("这次没有解析到 IP", "err", ipErr, "配置", cfg.Certificate.IPs)
	} else {
		slog.Info("将放入证书的 IP", "ips", formatIPs(ips))
	}
	if !config.RealEmail(cfg.Certificate.Email) {
		slog.Info("未配置邮箱，正式申请时会生成随机邮箱并写入 account.email")
	}
	if cfg.Certificate.Challenge == config.ChallengeHTTP {
		slog.Info("http-01 只在申请和续期时监听端口，结束后关闭", "port", cfg.Certificate.HTTPPort)
	}
}

// resolveConfigPath 在未指定 -config 时按顺序查找 go-tls-proxy.yml。
func resolveConfigPath(path string) string {
	if strings.TrimSpace(path) != "" {
		return path
	}
	candidates := []string{
		filepath.Join("config", "go-tls-proxy.yml"),
		"go-tls-proxy.yml",
	}
	for _, candidate := range candidates {
		st, err := os.Stat(candidate)
		if err == nil && !st.IsDir() {
			return candidate
		}
	}
	return filepath.Join("config", "go-tls-proxy.yml")
}

func formatIPs(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
