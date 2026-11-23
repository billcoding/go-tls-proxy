package cert

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var randomEmailRE = regexp.MustCompile(`^[0-9a-z]{8}@[0-9a-z]{8}\.com$`)

func TestRandomEmailFormat(t *testing.T) {
	a, b := randomEmail(), randomEmail()
	if !randomEmailRE.MatchString(a) || !randomEmailRE.MatchString(b) {
		t.Fatalf("%s %s", a, b)
	}
	if a == b {
		t.Fatal("两次生成不应相同")
	}
}

func TestResolveAccountEmailPersists(t *testing.T) {
	dir := t.TempDir()
	first, err := resolveAccountEmail(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !randomEmailRE.MatchString(first) {
		t.Fatal(first)
	}
	second, err := resolveAccountEmail(dir, "you@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("续期应沿用已保存邮箱 %s，得到 %s", first, second)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "account.email"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != first {
		t.Fatalf("file = %q", raw)
	}
}

func TestResolveAccountEmailReplacesUnusableSaved(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "account.email"), []byte("not-an-email\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAccountEmail(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if !randomEmailRE.MatchString(got) {
		t.Fatal(got)
	}
	again, err := resolveAccountEmail(dir, "you@example.com")
	if err != nil || again != got {
		t.Fatalf("%s %v", again, err)
	}
}

func TestResolveAccountEmailKeepsExplicit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "account.email"), []byte("aabbccdd@eeffgghh.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAccountEmail(dir, "ops@company.org")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ops@company.org" {
		t.Fatal(got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "account.email"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "ops@company.org" {
		t.Fatalf("file = %q", raw)
	}
	again, err := resolveAccountEmail(dir, "ops@company.org")
	if err != nil || again != "ops@company.org" {
		t.Fatalf("%s %v", again, err)
	}
}
