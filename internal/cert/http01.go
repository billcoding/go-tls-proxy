package cert

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// HTTP01 在证书校验期间应答 /.well-known/acme-challenge/。
// webroot 非空时把响应写成文件，交给已经占用 80 端口的 nginx 或其他 HTTP 服务。
type HTTP01 struct {
	mu        sync.RWMutex
	responses map[string]string
	webroot   string
	files     []string
}

func (h *HTTP01) setWebRoot(dir string) {
	h.mu.Lock()
	h.webroot = strings.TrimSpace(dir)
	h.mu.Unlock()
}

func (h *HTTP01) Set(path, body string) {
	token := tokenFromPath(path)
	if !validToken(token) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.webroot != "" {
		fp := filepath.Join(h.webroot, token)
		if err := os.WriteFile(fp, []byte(body), 0o644); err == nil {
			h.files = append(h.files, fp)
		}
		return
	}
	if h.responses == nil {
		h.responses = make(map[string]string)
	}
	h.responses[path] = body
}

func (h *HTTP01) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.responses = nil
	for _, fp := range h.files {
		_ = os.Remove(fp)
	}
	h.files = nil
	h.webroot = ""
}

func (h *HTTP01) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := tokenFromPath(r.URL.Path)
	if !validToken(token) {
		http.NotFound(w, r)
		return
	}
	h.mu.RLock()
	body, ok := h.responses[r.URL.Path]
	h.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}

func tokenFromPath(path string) string {
	path = strings.TrimSpace(path)
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}

func validToken(token string) bool {
	if token == "" || len(token) > 128 {
		return false
	}
	for _, c := range token {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}
