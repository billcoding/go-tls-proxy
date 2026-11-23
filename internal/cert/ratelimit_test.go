package cert

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestParseACMERetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	got := parseACMERetryAfter("120", "", now)
	if !got.Equal(now.Add(120 * time.Second)) {
		t.Fatalf("seconds = %s", got)
	}
	got = parseACMERetryAfter("", "Service busy; retry after 2026-11-19 03:04:05 UTC", now)
	want := time.Date(2026, 11, 19, 3, 4, 5, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("body = %s", got)
	}
	got = parseACMERetryAfter("", "no hint", now)
	if !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("fallback = %s", got)
	}
}

func TestRateLimitFileBlocksIssue(t *testing.T) {
	clearACMELimit()
	t.Cleanup(clearACMELimit)
	dir := t.TempDir()
	until := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	saveACMELimit(dir, until)
	clearACMELimit()
	loadACMELimit(dir)
	err := acmeRateWait(time.Now())
	var limited *acmeRateError
	if err == nil || !errorsAs(err, &limited) {
		t.Fatalf("err = %v", err)
	}
	if !limited.until.Equal(until) {
		t.Fatalf("until = %s", limited.until)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "acme-retry-after"))
	if err != nil || strings.TrimSpace(string(raw)) == "" {
		t.Fatal(err)
	}
}

func TestNoteTooManyRequests(t *testing.T) {
	clearACMELimit()
	t.Cleanup(clearACMELimit)
	dir := t.TempDir()
	in := &acme.Error{
		StatusCode:  http.StatusTooManyRequests,
		ProblemType: "urn:ietf:params:acme:error:rateLimited",
		Detail:      "retry after 2026-11-19 03:04:05 UTC",
		Header:      http.Header{"Retry-After": []string{"90"}},
	}
	err := noteACMEFailure(dir, in)
	var limited *acmeRateError
	if !errorsAs(err, &limited) {
		t.Fatal(err)
	}
	if time.Until(limited.until) < time.Minute {
		t.Fatalf("until = %s", limited.until)
	}
}

func errorsAs(err error, target **acmeRateError) bool {
	return err != nil && func() bool {
		var ok bool
		if limited, is := err.(*acmeRateError); is {
			*target = limited
			ok = true
		}
		return ok
	}()
}
