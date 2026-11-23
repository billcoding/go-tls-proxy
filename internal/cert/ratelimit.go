package cert

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// 对齐 cloudsystem/pkg/ipcert：把 Let's Encrypt 的 Retry-After 记到证书目录，
// 限流窗口内不再创建订单。404 / Invalid response 同样冷却 1 小时，避免连续打满配额。

var (
	acmeLimitMu sync.Mutex
	acmeLimitAt time.Time
)

type acmeRateError struct {
	until time.Time
	msg   string
}

func (e *acmeRateError) Error() string {
	if e == nil {
		return "ACME 限流"
	}
	if e.msg != "" {
		return e.msg
	}
	return "ACME 限流中，" + e.until.UTC().Format(time.RFC3339) + " 之前不再申请"
}

var acmeRetryAfterRE = regexp.MustCompile(`retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC`)

func parseACMERetryAfter(header, body string, now time.Time) time.Time {
	if sec, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && sec > 0 {
		return now.Add(time.Duration(sec) * time.Second)
	}
	if t, err := http.ParseTime(strings.TrimSpace(header)); err == nil {
		return t.UTC()
	}
	if m := acmeRetryAfterRE.FindStringSubmatch(body); len(m) == 2 {
		if t, err := time.Parse("2006-01-02 15:04:05", m[1]); err == nil {
			return t.UTC()
		}
	}
	return now.UTC().Add(time.Hour)
}

func rememberACMELimit(until time.Time) {
	if until.IsZero() {
		return
	}
	acmeLimitMu.Lock()
	if until.After(acmeLimitAt) {
		acmeLimitAt = until
	}
	acmeLimitMu.Unlock()
}

func saveACMELimit(dir string, until time.Time) {
	rememberACMELimit(until)
	if strings.TrimSpace(dir) == "" || until.IsZero() {
		return
	}
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(filepath.Join(dir, "acme-retry-after"), []byte(until.UTC().Format(time.RFC3339)), 0o600)
}

func loadACMELimit(dir string) {
	raw, err := os.ReadFile(filepath.Join(dir, "acme-retry-after"))
	if err != nil {
		return
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(raw)))
	if err != nil {
		return
	}
	rememberACMELimit(t)
}

func clearACMELimit() {
	acmeLimitMu.Lock()
	acmeLimitAt = time.Time{}
	acmeLimitMu.Unlock()
}

func acmeRateWait(now time.Time) error {
	acmeLimitMu.Lock()
	until := acmeLimitAt
	acmeLimitMu.Unlock()
	if !until.After(now) {
		return nil
	}
	return &acmeRateError{
		until: until,
		msg:   "ACME 限流中，" + until.UTC().Format(time.RFC3339) + " 之前不再申请",
	}
}

func noteACMEFailure(dir string, err error) error {
	if err == nil {
		return nil
	}
	var rl *acmeRateError
	if errors.As(err, &rl) {
		saveACMELimit(dir, rl.until)
		return err
	}
	var ae *acme.Error
	if errors.As(err, &ae) && ae.StatusCode == http.StatusTooManyRequests {
		header := ""
		if ae.Header != nil {
			header = ae.Header.Get("Retry-After")
		}
		until := parseACMERetryAfter(header, ae.Error(), time.Now())
		saveACMELimit(dir, until)
		return &acmeRateError{until: until, msg: err.Error()}
	}
	msg := err.Error()
	if strings.Contains(msg, "404") || strings.Contains(msg, "Invalid response") {
		saveACMELimit(dir, time.Now().Add(time.Hour))
	}
	return err
}
