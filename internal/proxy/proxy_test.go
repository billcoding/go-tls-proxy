package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/billcoding/go-tls-proxy/internal/config"
)

func TestLongestPathWins(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	handler, err := newHTTPHandler([]config.Route{
		{Path: "/", Backend: backend.URL},
		{Path: "/api", Backend: backend.URL},
		{Path: "/api/v1", Backend: backend.URL},
	}, false, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10/api/v1/items", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rr.Code)
	}
	if got != "/api/v1/items" {
		t.Fatalf("path = %s", got)
	}

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wrong", http.StatusTeapot)
	}))
	defer other.Close()
	handler, err = newHTTPHandler([]config.Route{
		{Path: "/", Backend: other.URL},
		{Path: "/api", Backend: backend.URL},
	}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "https://203.0.113.10/apiv2", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	body, _ := io.ReadAll(rr.Body)
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d body = %s", rr.Code, body)
	}
}

func TestRedirectLocation(t *testing.T) {
	handler, err := newHTTPHandler([]config.Route{
		{Path: "/app", Redirect: "https://203.0.113.10/base/", RedirectCode: http.StatusMovedPermanently},
		{Path: "/land", Redirect: "https://203.0.113.10/landing?from=old", RedirectCode: http.StatusFound},
		{Path: "/", Redirect: "https://203.0.113.10/", RedirectCode: http.StatusFound},
	}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		raw  string
		code int
		loc  string
	}{
		{"https://203.0.113.10/a/b?x=1", http.StatusFound, "https://203.0.113.10/a/b?x=1"},
		{"https://203.0.113.10/?x=1", http.StatusFound, "https://203.0.113.10/?x=1"},
		{"https://203.0.113.10/", http.StatusFound, "https://203.0.113.10/"},
		{"https://203.0.113.10/a/b/", http.StatusFound, "https://203.0.113.10/a/b/"},
		{"https://203.0.113.10/app/a/b?x=1", http.StatusMovedPermanently, "https://203.0.113.10/base/app/a/b?x=1"},
		{"https://203.0.113.10/app", http.StatusMovedPermanently, "https://203.0.113.10/base/app"},
		{"https://203.0.113.10/app/?x=1", http.StatusMovedPermanently, "https://203.0.113.10/base/app/?x=1"},
		{"https://203.0.113.10/land/a?x=1&y=2", http.StatusFound, "https://203.0.113.10/landing?from=old&x=1&y=2"},
		{"https://203.0.113.10/land", http.StatusFound, "https://203.0.113.10/landing?from=old"},
		{"https://203.0.113.10/a%20b?x=1", http.StatusFound, "https://203.0.113.10/a%20b?x=1"},
	}
	for _, tc := range checks {
		req := httptest.NewRequest(http.MethodGet, tc.raw, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != tc.code || rr.Header().Get("Location") != tc.loc {
			t.Fatalf("%s status=%d loc=%q want %d %q", tc.raw, rr.Code, rr.Header().Get("Location"), tc.code, tc.loc)
		}
	}

	hostOnly, err := newHTTPHandler([]config.Route{{
		Path:     "/",
		Redirect: "https://203.0.113.10",
	}}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10/a/b?x=1", nil)
	rr := httptest.NewRecorder()
	hostOnly.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "https://203.0.113.10/a/b?x=1" {
		t.Fatalf("host status=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestNamedRedirectLocation(t *testing.T) {
	handler, err := newHTTPHandler([]config.Route{
		{Path: "/abs", Redirect: "https://203.0.113.10/landing?from=old", RedirectCode: http.StatusFound},
		{Path: "/", Redirect: "app", RedirectCode: http.StatusFound, RedirectTo: &config.NamedRedirect{Scheme: "https", Port: "9001"}},
	}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.(*routeHandler).fallbackHost = func() string { return "198.51.100.20" }

	checks := []struct {
		raw  string
		host string
		code int
		loc  string
	}{
		{"https://203.0.113.10/a/b?x=1", "203.0.113.10:9080", http.StatusFound, "https://203.0.113.10:9001/a/b?x=1"},
		{"https://203.0.113.10/old/a/b?x=1&y=2", "203.0.113.10", http.StatusFound, "https://203.0.113.10:9001/old/a/b?x=1&y=2"},
		{"https://203.0.113.10/a%20b?x=1", "[2001:db8::10]:9080", http.StatusFound, "https://[2001:db8::10]:9001/a%20b?x=1"},
		{"https://203.0.113.10/", "", http.StatusFound, "https://198.51.100.20:9001/"},
		{"https://203.0.113.10/abs/a?x=1", "203.0.113.10:9080", http.StatusFound, "https://203.0.113.10/landing?from=old&x=1"},
		{"https://203.0.113.10/abs", "203.0.113.10:9080", http.StatusFound, "https://203.0.113.10/landing?from=old"},
	}
	for _, tc := range checks {
		req := httptest.NewRequest(http.MethodGet, tc.raw, nil)
		req.Host = tc.host
		if tc.host == "" {
			req.URL.Host = ""
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != tc.code || rr.Header().Get("Location") != tc.loc {
			t.Fatalf("%s host=%q status=%d loc=%q want %d %q", tc.raw, tc.host, rr.Code, rr.Header().Get("Location"), tc.code, tc.loc)
		}
	}

	plain, err := newHTTPHandler([]config.Route{{
		Path:         "/",
		Redirect:     "plain",
		RedirectCode: http.StatusMovedPermanently,
		RedirectTo:   &config.NamedRedirect{Scheme: "http", Port: "9081"},
	}}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://203.0.113.10:9080/a/b?x=1", nil)
	req.Host = "203.0.113.10:9080"
	rr := httptest.NewRecorder()
	plain.ServeHTTP(rr, req)
	if rr.Code != http.StatusMovedPermanently || rr.Header().Get("Location") != "http://203.0.113.10:9081/a/b?x=1" {
		t.Fatalf("plain status=%d loc=%q", rr.Code, rr.Header().Get("Location"))
	}
}

func TestPathMatches(t *testing.T) {
	if !pathMatches("/api/v1", "/api") {
		t.Fatal("prefix")
	}
	if pathMatches("/apiv2", "/api") {
		t.Fatal("partial")
	}
	if !pathMatches("/anywhere", "/") {
		t.Fatal("root")
	}
}
