package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// Manager 负责申请 IP 证书，并按固定周期更新。
type Manager struct {
	provider  *Provider
	http01    *HTTP01
	ips       []net.IP
	storage   string
	email     string
	directory string
	profile   string
	challenge string
	webRoot   string
	httpPort  int
	every     time.Duration
	staging   bool

	mu      sync.Mutex
	client  *acme.Client
	current *tls.Certificate
}

type Options struct {
	Provider   *Provider
	Email      string
	IPs        []net.IP
	StorageDir string
	Directory  string
	Profile    string
	Challenge  string
	WebRoot    string
	HTTPPort   int
	RenewEvery time.Duration
	Staging    bool
}

func NewManager(opts Options) *Manager {
	if opts.Provider == nil {
		opts.Provider = NewProvider()
	}
	if opts.HTTPPort == 0 {
		opts.HTTPPort = 80
	}
	return &Manager{
		provider:  opts.Provider,
		http01:    &HTTP01{},
		ips:       opts.IPs,
		storage:   opts.StorageDir,
		email:     opts.Email,
		directory: DirectoryFor(opts.Directory, opts.Staging),
		profile:   opts.Profile,
		challenge: opts.Challenge,
		webRoot:   strings.TrimSpace(opts.WebRoot),
		httpPort:  opts.HTTPPort,
		every:     opts.RenewEvery,
		staging:   opts.Staging,
	}
}

func (m *Manager) TLSConfig() *tls.Config {
	return m.provider.TLSConfig()
}

// Prepare 在端口开始监听前装上已有证书。没有可用证书时不签发任何证书，等 Run 向 Let's Encrypt 申请。
func (m *Manager) Prepare() error {
	cleanupHostFirewall(context.Background(), m.storage)
	if cert, ok := m.loadUsable(); ok {
		m.activate(cert)
		slog.Info("已加载证书",
			"not_after", cert.Leaf.NotAfter.Format(time.RFC3339),
			"renew_at", NextRenewAt(cert.Leaf.NotBefore, cert.Leaf.NotAfter, m.every).Format(time.RFC3339),
			"ips", ipStrings(cert.Leaf.IPAddresses),
		)
		return nil
	}
	slog.Info("还没有可用证书，启动后向 Let's Encrypt 申请")
	return nil
}

// Run 在需要时申请证书，之后按周期更新。上下文取消时返回。
func (m *Manager) Run(ctx context.Context) error {
	if err := m.Ensure(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return m.renewLoop(ctx)
}

// Ensure 在证书仍覆盖当前 IP 且未到更新时间时直接复用，否则申请或续期一次。
func (m *Manager) Ensure(ctx context.Context) error {
	cleanupHostFirewall(ctx, m.storage)
	if m.staging {
		slog.Warn("正在使用 Let's Encrypt 测试环境，浏览器不会信任这张证书")
	}
	current := m.snapshot()
	if current == nil {
		if loaded, ok := m.loadUsable(); ok {
			m.activate(loaded)
			current = loaded
		}
	}
	if current == nil || Due(current.Leaf, m.every, time.Now()) || !sameIPs(current.Leaf, m.ips) {
		return m.retryIssue(ctx)
	}
	slog.Info("证书仍可用",
		"not_after", current.Leaf.NotAfter.Format(time.RFC3339),
		"renew_at", NextRenewAt(current.Leaf.NotBefore, current.Leaf.NotAfter, m.every).Format(time.RFC3339),
		"ips", ipStrings(current.Leaf.IPAddresses),
	)
	return nil
}

func (m *Manager) retryIssue(ctx context.Context) error {
	backoff := 5 * time.Second
	for {
		cert, err := m.issue(ctx)
		if err == nil {
			slog.Info("证书已更新",
				"not_after", cert.Leaf.NotAfter.Format(time.RFC3339),
				"renew_at", NextRenewAt(cert.Leaf.NotBefore, cert.Leaf.NotAfter, m.every).Format(time.RFC3339),
				"ips", ipStrings(cert.Leaf.IPAddresses),
			)
			return nil
		}
		var permanent *permanentError
		if errors.As(err, &permanent) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var limited *acmeRateError
		if errors.As(err, &limited) {
			wait := time.Until(limited.until)
			if wait < 0 {
				wait = 0
			}
			slog.Error("ACME 限流，暂停申请", "retry_at", limited.until.UTC().Format(time.RFC3339), "err", err)
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		slog.Error("申请证书失败", "err", err, "retry_in", backoff.String())
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}

func (m *Manager) renewLoop(ctx context.Context) error {
	for {
		current := m.snapshot()
		wait := time.Minute
		if current != nil && current.Leaf != nil {
			wait = time.Until(NextRenewAt(current.Leaf.NotBefore, current.Leaf.NotAfter, m.every))
			if wait < 0 {
				wait = 0
			}
		}
		slog.Info("下次更新证书", "after", wait.Round(time.Second).String())
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if err := m.retryIssue(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func (m *Manager) issue(ctx context.Context) (*tls.Certificate, error) {
	unlock, err := lockDir(m.storage)
	if err != nil {
		return nil, err
	}
	defer unlock()

	cert, err := m.issueACME(ctx)
	if err != nil {
		return nil, err
	}
	if !sameIPs(cert.Leaf, m.ips) {
		return nil, fmt.Errorf("签发结果没有包含全部 IP: %s", ipStrings(m.ips))
	}
	if err := saveCertificate(m.storage, cert); err != nil {
		return nil, fmt.Errorf("保存证书: %w", err)
	}
	m.activate(cert)
	return cert, nil
}

func (m *Manager) activate(cert *tls.Certificate) {
	m.mu.Lock()
	m.current = cert
	m.mu.Unlock()
	m.provider.SetCertificate(cert)
}

func (m *Manager) snapshot() *tls.Certificate {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func (m *Manager) loadUsable() (*tls.Certificate, bool) {
	loaded, err := loadCertificate(m.storage)
	if err != nil {
		return nil, false
	}
	leaf := loaded.Leaf
	if leaf == nil || time.Until(leaf.NotAfter) < time.Minute {
		return nil, false
	}
	if !sameIPs(leaf, m.ips) {
		slog.Info("已保存的证书 IP 与配置不一致，将重新申请")
		return nil, false
	}
	return loaded, true
}

// NextRenewAt 返回应该发起更新的时间。周期到达前，若离过期不足 24 小时，会提前更新。
func NextRenewAt(notBefore, notAfter time.Time, every time.Duration) time.Time {
	at := notBefore.Add(every)
	safety := notAfter.Add(-24 * time.Hour)
	if safety.Before(at) {
		at = safety
	}
	if !at.Before(notAfter) {
		at = notAfter.Add(-time.Hour)
	}
	return at
}

// Due 表示现在是否已经到了更新时间。
func Due(leaf *x509.Certificate, every time.Duration, now time.Time) bool {
	if leaf == nil {
		return true
	}
	return !now.Before(NextRenewAt(leaf.NotBefore, leaf.NotAfter, every))
}

func sameIPs(leaf *x509.Certificate, want []net.IP) bool {
	if leaf == nil || len(leaf.IPAddresses) != len(want) {
		return false
	}
	for _, ip := range want {
		found := false
		for _, got := range leaf.IPAddresses {
			if got.Equal(ip) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}
