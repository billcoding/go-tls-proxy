package cert

import (
	"crypto/tls"
	"errors"
	"strings"
	"sync"

	"golang.org/x/crypto/acme"
)

// Provider 把当前服务证书和 ACME tls-alpn-01 校验证书交给所有 HTTPS 监听。
type Provider struct {
	mu         sync.RWMutex
	cert       *tls.Certificate
	challenges map[string]*tls.Certificate
}

func NewProvider() *Provider {
	return &Provider{}
}

func (p *Provider) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: p.GetCertificate,
		NextProtos: []string{
			"h2",
			"http/1.1",
			acme.ALPNProto,
		},
	}
}

func (p *Provider) SetCertificate(cert *tls.Certificate) {
	p.mu.Lock()
	p.cert = cert
	p.mu.Unlock()
}

func (p *Provider) Certificate() *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cert
}

func (p *Provider) SetChallenge(serverName string, cert *tls.Certificate) {
	copied := *cert
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.challenges == nil {
		p.challenges = make(map[string]*tls.Certificate)
	}
	p.challenges[normalizeSNI(serverName)] = &copied
}

func (p *Provider) ClearChallenges() {
	p.mu.Lock()
	p.challenges = nil
	p.mu.Unlock()
}

func (p *Provider) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello != nil && hasProto(hello.SupportedProtos, acme.ALPNProto) {
		if cert := p.challenge(hello.ServerName); cert != nil {
			return cert, nil
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.cert == nil {
		return nil, errors.New("证书还没有准备好")
	}
	return p.cert, nil
}

func (p *Provider) challenge(serverName string) *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.challenges == nil {
		return nil
	}
	return p.challenges[normalizeSNI(serverName)]
}

func normalizeSNI(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func hasProto(protos []string, want string) bool {
	for _, proto := range protos {
		if proto == want {
			return true
		}
	}
	return false
}
