package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestReversePointer(t *testing.T) {
	v4, err := reversePointer(net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if v4 != "1.2.0.192.in-addr.arpa" {
		t.Fatalf("v4 = %s", v4)
	}
	v6, err := reversePointer(net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if v6 != want {
		t.Fatalf("v6 = %s", v6)
	}
}

func TestParsePublicIP(t *testing.T) {
	ip, err := parsePublicIP("203.0.113.10\n")
	if err != nil || ip.String() != "203.0.113.10" {
		t.Fatalf("%v %v", ip, err)
	}
	ip, err = parsePublicIP("fl=1\nip=198.51.100.20\nts=1\n")
	if err != nil || ip.String() != "198.51.100.20" {
		t.Fatalf("trace %v %v", ip, err)
	}
	if _, err = parsePublicIP("10.1.2.3"); err == nil {
		t.Fatal("内网地址")
	}
	t.Setenv("GO_TLS_PROXY_PUBLIC_IP", "203.0.113.9")
	got, err := detectPublic(t.Context())
	if err != nil || len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestPublicIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"203.0.113.10", true},
		{"10.1.2.3", false},
		{"192.168.1.1", false},
		{"127.0.0.1", false},
		{"100.64.1.1", false},
		{"169.254.1.1", false},
	}
	for _, tc := range cases {
		if got := PublicIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Fatalf("%s = %v", tc.ip, got)
		}
	}
}

func TestNextRenewAt(t *testing.T) {
	start := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	end := start.Add(160 * time.Hour)
	got := NextRenewAt(start, end, 72*time.Hour)
	if !got.Equal(start.Add(72 * time.Hour)) {
		t.Fatalf("renew = %s", got)
	}
	shortEnd := start.Add(48 * time.Hour)
	got = NextRenewAt(start, shortEnd, 72*time.Hour)
	if !got.Equal(shortEnd.Add(-24 * time.Hour)) {
		t.Fatalf("safety = %s", got)
	}

	leaf := &x509.Certificate{
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(96 * time.Hour),
	}
	if Due(leaf, 72*time.Hour, time.Now()) {
		t.Fatal("新证书不应该立刻更新")
	}
	if !Due(leaf, 72*time.Hour, time.Now().Add(73*time.Hour)) {
		t.Fatal("过了更新周期应该更新")
	}
}

func TestProviderChallengeSNI(t *testing.T) {
	p := NewProvider()
	service := certWithIP("203.0.113.10")
	p.SetCertificate(service)
	challenge := certWithIP("203.0.113.11")
	p.SetChallenge("10.113.0.203.in-addr.arpa.", challenge)

	got, err := p.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "10.113.0.203.IN-ADDR.ARPA",
		SupportedProtos: []string{acme.ALPNProto},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Leaf.IPAddresses[0].Equal(net.ParseIP("203.0.113.11")) {
		t.Fatalf("challenge ip = %v", got.Leaf.IPAddresses)
	}

	got, err = p.GetCertificate(&tls.ClientHelloInfo{
		ServerName:      "10.113.0.203.in-addr.arpa",
		SupportedProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Leaf.IPAddresses[0].Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("service ip = %v", got.Leaf.IPAddresses)
	}
}

func TestPrepareDoesNotMintCertificate(t *testing.T) {
	oldLook := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	t.Cleanup(func() { lookPath = oldLook })
	dir := t.TempDir()
	m := NewManager(Options{
		IPs:        []net.IP{net.ParseIP("203.0.113.10")},
		StorageDir: dir,
		RenewEvery: 72 * time.Hour,
	})
	if err := m.Prepare(); err != nil {
		t.Fatal(err)
	}
	if m.snapshot() != nil {
		t.Fatal("没有已保存证书时不应装上证书")
	}
	if _, err := os.Stat(filepath.Join(dir, "cert.pem")); !os.IsNotExist(err) {
		t.Fatal("不应写出证书")
	}
}

func certWithIP(ip string) *tls.Certificate {
	return &tls.Certificate{
		Leaf: &x509.Certificate{IPAddresses: []net.IP{net.ParseIP(ip)}},
	}
}
