package cert

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
)

// 与 cloudsystem/pkg/ipcert/account.go 相同：8 位小写字母或数字，@，再 8 位，以 .com 结尾。
// 写到证书目录的 account.email。文件里已有带 @ 且以 .com 结尾的地址就继续用，不会每次重生成。

func randomEmail() string {
	return randomToken(8) + "@" + randomToken(8) + ".com"
}

func randomToken(n int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	rb := make([]byte, n)
	_, _ = rand.Read(rb)
	for i := range buf {
		buf[i] = alphabet[int(rb[i])%len(alphabet)]
	}
	return string(buf)
}

// resolveAccountEmail 决定注册 ACME 账户用的邮箱。
// 配置里写了非占位邮箱时用配置，并记到 account.email。
// 配置为空或仍是 @example.com 时，复用已保存的随机邮箱；没有合格记录才新生成。
func resolveAccountEmail(dir, configured string) (string, error) {
	configured = strings.TrimSpace(configured)
	if explicitAccountEmail(configured) {
		if err := saveAccountEmail(dir, configured); err != nil {
			return "", err
		}
		return configured, nil
	}
	email := strings.TrimSpace(readSmall(filepath.Join(dir, "account.email")))
	if strings.Contains(email, "@") && strings.HasSuffix(strings.ToLower(email), ".com") {
		return email, nil
	}
	email = randomEmail()
	if err := saveAccountEmail(dir, email); err != nil {
		return "", err
	}
	return email, nil
}

func explicitAccountEmail(email string) bool {
	email = strings.TrimSpace(email)
	return strings.Contains(email, "@") && !strings.HasSuffix(strings.ToLower(email), "@example.com")
}

func saveAccountEmail(dir, email string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "account.email"), []byte(email+"\n"), 0o600)
}

func readSmall(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
