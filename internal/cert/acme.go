package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	letsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// DirectoryFor 返回实际使用的 ACME 目录。显式地址优先，否则按是否测试环境选择 Let's Encrypt。
func DirectoryFor(explicit string, staging bool) string {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		return explicit
	}
	if staging {
		return letsEncryptStaging
	}
	return letsEncryptProduction
}

func (m *Manager) issueACME(ctx context.Context) (cert *tls.Certificate, err error) {
	if len(m.ips) > 25 {
		return nil, permanent(fmt.Errorf("Let's Encrypt 单张证书最多包含 25 个 IP，当前有 %d 个", len(m.ips)))
	}
	for _, ip := range m.ips {
		if !PublicIP(ip) {
			return nil, permanent(fmt.Errorf("Let's Encrypt 不能给 %s 签发证书，证书 IP 必须是公网地址", ip))
		}
	}
	loadACMELimit(m.storage)
	if err = acmeRateWait(time.Now()); err != nil {
		return nil, err
	}
	stopHTTP, err := m.openHTTP01(ctx)
	if err != nil {
		return nil, err
	}
	defer stopHTTP()
	defer func() {
		if err != nil && ctx.Err() == nil {
			err = noteACMEFailure(m.storage, err)
		}
	}()

	client, err := m.acmeClient(ctx)
	if err != nil {
		return nil, err
	}
	order, err := client.AuthorizeOrder(ctx, acme.IPIDs(ipStrings(m.ips)...), acme.WithOrderIssuanceProfile(acme.ProfileName(m.profile)))
	if err != nil {
		return nil, fmt.Errorf("创建证书订单: %w", err)
	}
	defer m.provider.ClearChallenges()
	defer m.http01.Clear()

	if err := m.completeAuthorizations(ctx, client, order); err != nil {
		return nil, err
	}
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("等待订单完成: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ips, err := orderIPs(ready)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{IPAddresses: ips}, key)
	if err != nil {
		return nil, err
	}

	var ders [][]byte
	if ready.Status == acme.StatusValid && ready.CertURL != "" {
		ders, err = client.FetchCert(ctx, ready.CertURL, true)
	} else {
		ders, _, err = client.CreateCertFromOrder(ctx, ready, csr, true)
	}
	if err != nil {
		return nil, fmt.Errorf("下载证书: %w", err)
	}
	return certificateFrom(key, ders)
}

func (m *Manager) acmeClient(ctx context.Context) (*acme.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		return m.client, nil
	}
	key, err := loadOrCreateAccountKey(m.storage)
	if err != nil {
		return nil, fmt.Errorf("读取 ACME 账户: %w", err)
	}
	contact, err := resolveAccountEmail(m.storage, m.email)
	if err != nil {
		return nil, fmt.Errorf("准备 ACME 邮箱: %w", err)
	}
	m.email = contact
	slog.Info("ACME 账户邮箱", "email", contact)
	client := &acme.Client{
		Key:          key,
		DirectoryURL: m.directory,
		UserAgent:    "go-tls-proxy",
		HTTPClient:   &http.Client{Timeout: 2 * time.Minute},
	}
	if !strings.HasPrefix(contact, "mailto:") {
		contact = "mailto:" + contact
	}
	_, err = client.Register(ctx, &acme.Account{Contact: []string{contact}}, acme.AcceptTOS)
	if err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("注册 ACME 账户: %w", err)
	}
	m.client = client
	return client, nil
}

func (m *Manager) completeAuthorizations(ctx context.Context, client *acme.Client, order *acme.Order) error {
	var pending []string
	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("读取授权: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		challenge := pickChallenge(authz, m.challenge)
		if challenge == nil {
			return fmt.Errorf("%s 的授权里没有 %s 校验", authz.Identifier.Value, m.challenge)
		}
		if err := m.present(client, authz, challenge); err != nil {
			return err
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return fmt.Errorf("提交 %s 的校验: %w", authz.Identifier.Value, err)
		}
		pending = append(pending, authz.URI)
	}
	for _, authzURL := range pending {
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("证书校验没有通过: %w", err)
		}
	}
	return nil
}

func (m *Manager) present(client *acme.Client, authz *acme.Authorization, challenge *acme.Challenge) error {
	switch challenge.Type {
	case "tls-alpn-01":
		leaf, err := client.TLSALPN01ChallengeCert(challenge.Token, authz.Identifier.Value)
		if err != nil {
			return fmt.Errorf("生成 tls-alpn-01 证书: %w", err)
		}
		ip := net.ParseIP(authz.Identifier.Value)
		names, err := challengeNames(ip)
		if err != nil {
			return err
		}
		for _, name := range names {
			m.provider.SetChallenge(name, &leaf)
		}
		slog.Info("等待 tls-alpn-01 校验", "ip", authz.Identifier.Value, "sni", names[0])
	case "http-01":
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return err
		}
		path := client.HTTP01ChallengePath(challenge.Token)
		m.http01.Set(path, response)
		slog.Info("等待 http-01 校验", "ip", authz.Identifier.Value, "path", path)
	default:
		return fmt.Errorf("不支持的校验类型 %s", challenge.Type)
	}
	return nil
}

func pickChallenge(authz *acme.Authorization, want string) *acme.Challenge {
	for _, challenge := range authz.Challenges {
		if challenge.Type == want {
			return challenge
		}
	}
	return nil
}

func orderIPs(order *acme.Order) ([]net.IP, error) {
	var ips []net.IP
	for _, id := range order.Identifiers {
		if id.Type != "ip" {
			return nil, fmt.Errorf("订单包含非 IP 标识 %s", id.Value)
		}
		ip := net.ParseIP(id.Value)
		if ip == nil {
			return nil, fmt.Errorf("订单里的 IP 无效: %s", id.Value)
		}
		ips = append(ips, canonicalIP(ip))
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("订单里没有 IP")
	}
	return ips, nil
}

func certificateFrom(key crypto.Signer, ders [][]byte) (*tls.Certificate, error) {
	if len(ders) == 0 {
		return nil, fmt.Errorf("证书机构没有返回证书")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil, fmt.Errorf("解析证书: %w", err)
	}
	return &tls.Certificate{Certificate: ders, PrivateKey: key, Leaf: leaf}, nil
}
