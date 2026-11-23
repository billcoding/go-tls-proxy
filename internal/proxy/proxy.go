package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/billcoding/go-tls-proxy/internal/config"
	"github.com/billcoding/go-tls-proxy/internal/docker"
)

type Options struct {
	EnableACME bool
	Challenge  string
	Docker     config.Docker
}

type Server struct {
	ctx         context.Context
	cancel      context.CancelFunc
	httpServers []*http.Server
	httpLns     []net.Listener
	tcp         []tcpProxy
}

type tcpProxy struct {
	ln       net.Listener
	name     string
	backend  string
	resolver *docker.Resolver
}

func New(proxies []config.Proxy, tlsConfig *tls.Config, opts Options) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver, err := newResolver(proxies, opts.Docker)
	if err != nil {
		cancel()
		return nil, err
	}
	s := &Server{ctx: ctx, cancel: cancel}
	success := false
	defer func() {
		if !success {
			s.closeAll()
		}
	}()

	pairs := sharedListenPairs(proxies)
	started := map[int]bool{}
	for i := range proxies {
		if started[i] {
			continue
		}
		if j, ok := pairs[i]; ok {
			started[i] = true
			started[j] = true
			if err := s.serveShared(proxies[i], proxies[j], tlsConfig, resolver); err != nil {
				return nil, err
			}
			continue
		}
		if err := s.serveOne(proxies[i], tlsConfig, resolver); err != nil {
			return nil, err
		}
	}

	if opts.EnableACME && opts.Challenge == config.ChallengeTLSALPN && !config.UsesPort(proxies, 443) {
		ln, err := net.Listen("tcp", ":443")
		if err != nil {
			return nil, fmt.Errorf("监听证书校验端口 :443: %w", err)
		}
		tlsLn := newReadyListener(ctx, ln, tlsConfig)
		s.httpLns = append(s.httpLns, tlsLn)
		s.httpServers = append(s.httpServers, &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, "go-tls-proxy\n")
			}),
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       30 * time.Second,
		})
		slog.Info("已打开 443 端口用于 IP 证书校验")
	}

	success = true
	return s, nil
}

func sharedListenPairs(proxies []config.Proxy) map[int]int {
	pairs := map[int]int{}
	for i := range proxies {
		if _, ok := pairs[i]; ok {
			continue
		}
		for j := i + 1; j < len(proxies); j++ {
			if _, ok := pairs[j]; ok {
				continue
			}
			if config.ShareListen(proxies[i], proxies[j]) {
				pairs[i] = j
				pairs[j] = i
				break
			}
		}
	}
	return pairs
}

func (s *Server) serveOne(item config.Proxy, tlsConfig *tls.Config, resolver *docker.Resolver) error {
	ln, err := net.Listen("tcp", item.Listen)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", item.Listen, err)
	}
	// tls: false 只让 http 模式明文监听。TCP 和默认 http 仍包一层 TLS。
	var serveLn net.Listener
	if item.PlainHTTP() {
		serveLn = ln
	} else {
		listenerTLS := tlsConfig
		if item.Mode == config.ModeTCP {
			listenerTLS = tcpTLSConfig(tlsConfig)
		}
		serveLn = newReadyListener(s.ctx, ln, listenerTLS)
	}

	switch item.Mode {
	case config.ModeHTTP:
		return s.addHTTP(serveLn, item, tlsConfig, resolver)
	case config.ModeTCP:
		s.tcp = append(s.tcp, tcpProxy{ln: serveLn, name: item.Name, backend: item.Backend, resolver: resolver})
		slog.Info("TCP 反向代理", "name", item.Name, "listen", item.Listen, "backend", item.Backend)
		return nil
	default:
		_ = serveLn.Close()
		return fmt.Errorf("代理 %s 的模式无效", item.Name)
	}
}

// serveShared 用一个套接字同时接明文和 HTTPS。开头是 TLS ClientHello 交给 HTTPS，其余交给明文。
func (s *Server) serveShared(a, b config.Proxy, tlsConfig *tls.Config, resolver *docker.Resolver) error {
	plain, secure := a, b
	if !plain.PlainHTTP() {
		plain, secure = secure, plain
	}
	ln, err := net.Listen("tcp", plain.Listen)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", plain.Listen, err)
	}
	plainLn, tlsLn := newSplitListeners(s.ctx, ln)
	httpsLn := newReadyListener(s.ctx, tlsLn, tlsConfig)
	if err := s.addHTTP(plainLn, plain, tlsConfig, resolver); err != nil {
		_ = httpsLn.Close()
		return err
	}
	if err := s.addHTTP(httpsLn, secure, tlsConfig, resolver); err != nil {
		return err
	}
	slog.Info("同一端口分流明文和 HTTPS", "listen", ln.Addr().String(), "http", plain.Name, "https", secure.Name)
	return nil
}

func (s *Server) addHTTP(ln net.Listener, item config.Proxy, tlsConfig *tls.Config, resolver *docker.Resolver) error {
	handler, err := newHTTPHandler(item.Routes, item.InsecureSkipVerify, resolver)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("代理 %s: %w", item.Name, err)
	}
	if rh, ok := handler.(*routeHandler); ok {
		rh.fallbackHost = func() string { return hostFromCertificate(tlsConfig) }
	}
	s.httpLns = append(s.httpLns, ln)
	s.httpServers = append(s.httpServers, &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	})
	slog.Info("HTTP 反向代理", "name", item.Name, "listen", item.Listen, "tls", !item.PlainHTTP(), "routes", routeLog(item.Routes))
	return nil
}

func (s *Server) Start() {
	for _, item := range s.tcp {
		go serveTCP(s.ctx, item.ln, item.name, item.backend, item.resolver)
	}
	for i, srv := range s.httpServers {
		ln := s.httpLns[i]
		go func(srv *http.Server, ln net.Listener) {
			err := srv.Serve(ln)
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				slog.Error("HTTP 服务退出", "addr", ln.Addr().String(), "err", err)
			}
		}(srv, ln)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	var wg sync.WaitGroup
	errCh := make(chan error, len(s.httpServers)+len(s.httpLns)+len(s.tcp))
	for _, srv := range s.httpServers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		}(srv)
	}
	wg.Wait()
	s.closeAll()
	close(errCh)
	var joined error
	for err := range errCh {
		joined = errors.Join(joined, err)
	}
	return joined
}

func (s *Server) closeAll() {
	s.cancel()
	for _, ln := range s.httpLns {
		_ = ln.Close()
	}
	for _, item := range s.tcp {
		_ = item.ln.Close()
	}
}

type routeHandler struct {
	routes       []compiledRoute
	fallbackHost func() string
}

type compiledRoute struct {
	path        string
	proxy       *httputil.ReverseProxy
	redirect    *url.URL
	code        int
	namedScheme string
	namedPort   string
}

func newHTTPHandler(routes []config.Route, insecure bool, resolver *docker.Resolver) (http.Handler, error) {
	compiled := make([]compiledRoute, 0, len(routes))
	for _, route := range routes {
		item := compiledRoute{path: route.Path}
		if route.Redirect != "" {
			code := route.RedirectCode
			if code == 0 {
				code = http.StatusFound
			}
			item.code = code
			if route.RedirectTo != nil {
				if (route.RedirectTo.Scheme != "http" && route.RedirectTo.Scheme != "https") || route.RedirectTo.Port == "" {
					return nil, fmt.Errorf("redirect 无效: %s", route.Redirect)
				}
				item.namedScheme = route.RedirectTo.Scheme
				item.namedPort = route.RedirectTo.Port
				compiled = append(compiled, item)
				continue
			}
			target, err := url.Parse(route.Redirect)
			if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
				return nil, fmt.Errorf("redirect 无效: %s", route.Redirect)
			}
			item.redirect = target
			compiled = append(compiled, item)
			continue
		}
		proxy, err := newRouteProxy(route, insecure, resolver)
		if err != nil {
			return nil, err
		}
		item.proxy = proxy
		compiled = append(compiled, item)
	}
	sortRoutes(compiled)
	return &routeHandler{routes: compiled}, nil
}

type resolveError struct {
	err error
}

func (e *resolveError) Error() string { return e.err.Error() }
func (e *resolveError) Unwrap() error { return e.err }

type resolveErrKey struct{}

type dockerRoute struct {
	resolver *docker.Resolver
	name     string
	port     string
	upstream *url.URL
}

type dockerRouteKey struct{}

type dockerRetriedKey struct{}

var errSameDockerAddr = errors.New("docker address unchanged")

type resolveTransport struct {
	base http.RoundTripper
}

func (t resolveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err, ok := req.Context().Value(resolveErrKey{}).(*resolveError); ok && err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func newDockerTransport(insecure bool) *http.Transport {
	transport := newTransport(insecure)
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialDocker(ctx, dial, network, addr)
	}
	return transport
}

// dialDocker 在拒绝连接、没有路由或拨号超时时丢掉缓存，再按容器名查一次。
// 第二次拨号仍失败就作废新缓存。查询和拨号都发生在写出请求体之前。
func dialDocker(ctx context.Context, base func(context.Context, string, string) (net.Conn, error), network, addr string) (net.Conn, error) {
	if ctx.Value(dockerRetriedKey{}) != nil {
		return base(ctx, network, addr)
	}
	conn, err := base(ctx, network, addr)
	if err == nil || ctx.Err() != nil || !isConnectFailure(err) {
		return conn, err
	}
	route, ok := ctx.Value(dockerRouteKey{}).(dockerRoute)
	if !ok || route.resolver == nil {
		return nil, err
	}
	addr2, rerr := refreshDockerAddr(ctx, route.resolver, route.name, route.port, addr)
	if rerr != nil {
		if errors.Is(rerr, errSameDockerAddr) {
			return nil, err
		}
		return nil, &resolveError{err: rerr}
	}
	if route.upstream != nil {
		route.upstream.Host = addr2
	}
	conn, err = base(context.WithValue(ctx, dockerRetriedKey{}, true), network, addr2)
	if isConnectFailure(err) {
		route.resolver.Forget(route.name, route.port)
		return nil, err
	}
	if err == nil {
		slog.Debug("容器地址连接失败，已改用新地址", "container", route.name, "from", addr, "to", addr2)
	}
	return conn, err
}

// isConnectFailure 判断是不是「地址本身连不上」：拒绝连接、没有路由、网络不可达、拨号超时。
// 调用方取消了请求，或连接建立之后的读写错误，不算。拨号器自己的超时算。
func isConnectFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// refreshDockerAddr 丢掉缓存后再问一次 Docker。地址与 previous 相同，或查询失败时，不保留这次结果。
func refreshDockerAddr(ctx context.Context, resolver *docker.Resolver, name, port, previous string) (string, error) {
	resolver.Forget(name, port)
	addr, err := resolver.Resolve(ctx, name, port, true)
	if err != nil {
		return "", err
	}
	if addr == previous {
		resolver.Forget(name, port)
		return "", errSameDockerAddr
	}
	return addr, nil
}

func newRouteProxy(route config.Route, insecure bool, resolver *docker.Resolver) (*httputil.ReverseProxy, error) {
	if config.IsDockerBackend(route.Backend) {
		name, port, err := config.ParseDockerBackend(route.Backend)
		if err != nil {
			return nil, err
		}
		if resolver == nil {
			return nil, fmt.Errorf("后端 %s 需要 Docker", route.Backend)
		}
		label := route.Backend
		return &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				ctx := context.WithValue(pr.Out.Context(), dockerRouteKey{}, dockerRoute{
					resolver: resolver,
					name:     name,
					port:     port,
					upstream: pr.Out.URL,
				})
				addr, err := resolver.Resolve(pr.In.Context(), name, port, false)
				if err != nil {
					ctx = context.WithValue(ctx, resolveErrKey{}, &resolveError{err: err})
					pr.Out = pr.Out.WithContext(ctx)
					pr.SetURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1"})
					return
				}
				pr.Out = pr.Out.WithContext(ctx)
				pr.SetURL(&url.URL{Scheme: "http", Host: addr})
				// Host 留空，发出去的 Host 头才会用 URL.Host。拨号失败改地址时改的是同一个 URL。
				pr.SetXForwarded()
			},
			Transport:     resolveTransport{base: newDockerTransport(insecure)},
			FlushInterval: -1, // 负数：每写一块就发给客户端，不为小响应攒包
			BufferPool:    copyPool{},
			ErrorHandler:  badGateway(label),
		}, nil
	}
	target, err := url.Parse(route.Backend)
	if err != nil {
		return nil, err
	}
	backend := target
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(backend)
			pr.Out.Host = backend.Host
			pr.SetXForwarded()
		},
		Transport:     newTransport(insecure),
		FlushInterval: -1, // 负数：每写一块就发给客户端，不为小响应攒包
		BufferPool:    copyPool{},
		ErrorHandler:  badGateway(backend.Host),
	}, nil
}

func badGateway(backend string) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		msg := "转发失败"
		var resolved *resolveError
		if errors.As(err, &resolved) {
			msg = "解析容器失败"
			err = resolved.err
		}
		slog.Error(msg, "path", r.URL.Path, "backend", backend, "err", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
}

func newResolver(proxies []config.Proxy, cfg config.Docker) (*docker.Resolver, error) {
	if !needsDocker(proxies) {
		return nil, nil
	}
	return docker.New(cfg.Socket)
}

func needsDocker(proxies []config.Proxy) bool {
	for _, item := range proxies {
		if config.IsDockerBackend(item.Backend) {
			return true
		}
		for _, route := range item.Routes {
			if config.IsDockerBackend(route.Backend) {
				return true
			}
		}
	}
	return false
}

func backendAddr(ctx context.Context, backend string, resolver *docker.Resolver) (string, error) {
	if !config.IsDockerBackend(backend) {
		return backend, nil
	}
	if resolver == nil {
		return "", fmt.Errorf("后端 %s 需要 Docker", backend)
	}
	name, port, err := config.ParseDockerBackend(backend)
	if err != nil {
		return "", err
	}
	// 短缓存内复用上次的 IP。缓存过期，或连接失败后 Forget，下次才会再问 Docker。
	return resolver.Resolve(ctx, name, port, false)
}

func (h *routeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := matchRoute(r.URL.Path, h.routes)
	if route == nil {
		http.NotFound(w, r)
		return
	}
	if route.namedPort != "" {
		host := requestRedirectHost(r)
		if host == "" && h.fallbackHost != nil {
			host = h.fallbackHost()
		}
		if host == "" {
			slog.Error("重定向缺少主机", "path", r.URL.Path)
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		target := &url.URL{Scheme: route.namedScheme, Host: net.JoinHostPort(host, route.namedPort)}
		http.Redirect(w, r, redirectLocation(target, r), route.code)
		return
	}
	if route.redirect != nil {
		http.Redirect(w, r, redirectLocation(route.redirect, r), route.code)
		return
	}
	route.proxy.ServeHTTP(w, r)
}

// requestRedirectHost 取请求里的主机并去掉端口。按名跳转时再换上目标代理的端口。
func requestRedirectHost(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	if host == "" {
		return ""
	}
	if name, _, err := net.SplitHostPort(host); err == nil {
		return name
	}
	return strings.Trim(host, "[]")
}

// hostFromCertificate 取当前证书上的地址。优先 IPv4，供 Host 为空时写入 Location。
func hostFromCertificate(cfg *tls.Config) string {
	if cfg == nil || cfg.GetCertificate == nil {
		return ""
	}
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || cert == nil {
		return ""
	}
	leaf := cert.Leaf
	if leaf == nil && len(cert.Certificate) > 0 {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return ""
		}
		leaf = parsed
	}
	if leaf == nil {
		return ""
	}
	var v4, other net.IP
	for _, ip := range leaf.IPAddresses {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if v4 == nil {
				v4 = ip
			}
			continue
		}
		if other == nil {
			other = ip
		}
	}
	if v4 != nil {
		return v4.String()
	}
	if other != nil {
		return other.String()
	}
	return ""
}

// redirectLocation 拼出带 scheme 和主机的完整地址，交给 http.Redirect 写入 Location。
// 目标路径为空，或以 / 结尾时，接上原请求路径。请求路径是 / 时不再多加一段。
// 目标已经写了不以 / 结尾的具体路径时，就用这个路径，不再接原路径。
// 两种情况都保留原查询串。目标自己有查询串时放在前面，用 & 接上原查询串。
func redirectLocation(target *url.URL, r *http.Request) string {
	u := *target
	reqPath := r.URL.Path
	if reqPath == "" {
		reqPath = "/"
	}
	if u.Path == "" || strings.HasSuffix(u.Path, "/") {
		u.RawPath = ""
		u.Path = joinRedirectPath(u.Path, reqPath)
	}
	u.RawQuery = mergeQuery(target.RawQuery, r.URL.RawQuery)
	return u.String()
}

func joinRedirectPath(base, reqPath string) string {
	if base == "" {
		base = "/"
	}
	if reqPath == "/" {
		return base
	}
	return base + strings.TrimPrefix(reqPath, "/")
}

func mergeQuery(target, request string) string {
	switch {
	case target == "":
		return request
	case request == "":
		return target
	default:
		return target + "&" + request
	}
}

func matchRoute(path string, routes []compiledRoute) *compiledRoute {
	for i := range routes {
		if pathMatches(path, routes[i].path) {
			return &routes[i]
		}
	}
	return nil
}

func pathMatches(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	return path == prefix || len(path) > len(prefix) && path[:len(prefix)] == prefix && path[len(prefix)] == '/'
}

func sortRoutes(routes []compiledRoute) {
	for i := 1; i < len(routes); i++ {
		item := routes[i]
		j := i
		for j > 0 && len(routes[j-1].path) < len(item.path) {
			routes[j] = routes[j-1]
			j--
		}
		routes[j] = item
	}
}

func newTransport(insecure bool) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			setNoDelay(conn)
			return conn, nil
		},
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 0,
		ReadBufferSize:        64 << 10,
		WriteBufferSize:       64 << 10,
	}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return transport
}

func serveTCP(ctx context.Context, ln net.Listener, name, backend string, resolver *docker.Resolver) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Error("接受 TCP 连接失败", "name", name, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		go tunnel(ctx, conn, name, backend, resolver)
	}
}

func connectBackend(ctx context.Context, backend string, resolver *docker.Resolver) (net.Conn, string, error) {
	addr, err := backendAddr(ctx, backend, resolver)
	if err != nil {
		return nil, "", err
	}
	conn, err := dialTCP(ctx, addr)
	if err == nil || resolver == nil || !config.IsDockerBackend(backend) || ctx.Err() != nil || !isConnectFailure(err) {
		return conn, addr, err
	}
	name, port, perr := config.ParseDockerBackend(backend)
	if perr != nil {
		return nil, addr, err
	}
	addr2, rerr := refreshDockerAddr(ctx, resolver, name, port, addr)
	if rerr != nil {
		if errors.Is(rerr, errSameDockerAddr) {
			return nil, addr, err
		}
		return nil, "", rerr
	}
	conn, err = dialTCP(ctx, addr2)
	if err != nil {
		if isConnectFailure(err) {
			resolver.Forget(name, port)
		}
		return nil, addr2, err
	}
	slog.Debug("容器地址连接失败，已改用新地址", "from", addr, "to", addr2)
	return conn, addr2, nil
}

func tunnel(ctx context.Context, client net.Conn, name, backend string, resolver *docker.Resolver) {
	defer client.Close()
	setNoDelay(client)
	upstream, addr, err := connectBackend(ctx, backend, resolver)
	if err != nil {
		if addr == "" {
			slog.Error("解析容器失败", "name", name, "backend", backend, "err", err)
			return
		}
		slog.Error("连接后端失败", "name", name, "backend", addr, "err", err)
		return
	}
	defer upstream.Close()
	slog.Debug("TCP 已连接", "name", name, "remote", client.RemoteAddr().String(), "backend", addr)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		relay(upstream, client)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		relay(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
}

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	setNoDelay(conn)
	return conn, nil
}

const copyBufSize = 128 << 10

var copyBufPool = sync.Pool{
	New: func() any {
		return make([]byte, copyBufSize)
	},
}

type copyPool struct{}

func (copyPool) Get() []byte { return copyBufPool.Get().([]byte) }

func (copyPool) Put(b []byte) {
	if cap(b) < copyBufSize {
		return
	}
	copyBufPool.Put(b[:copyBufSize])
}

// relay 用大缓冲拷贝。不用 io.Copy：一端是 TLS 时，标准库会退回 32KB 缓冲，而且不会用到我们传入的切片。
func relay(dst io.Writer, src io.Reader) {
	buf := copyBufPool.Get().([]byte)
	defer copyBufPool.Put(buf[:copyBufSize])
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if ew != nil || nw != nr {
				return
			}
		}
		if er != nil {
			return
		}
	}
}

type tcpConnUnwrapper interface {
	NetConn() net.Conn
}

func setNoDelay(conn net.Conn) {
	for range 4 {
		switch c := conn.(type) {
		case *net.TCPConn:
			_ = c.SetNoDelay(true)
			return
		case tcpConnUnwrapper:
			next := c.NetConn()
			if next == nil || next == conn {
				return
			}
			conn = next
		default:
			return
		}
	}
}

func closeWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = conn.Close()
}

// tcpTLSConfig 用于按字节转发的 TLS 端口。不能宣布 h2：浏览器会改说 HTTP/2，
// 而后端（如 Gogs）只回 HTTP/1.1，页面就会是 ERR_HTTP2_PROTOCOL_ERROR。
func tcpTLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.NextProtos = []string{"http/1.1", acme.ALPNProto}
	return cfg
}

func routeLog(routes []config.Route) []string {
	out := make([]string, len(routes))
	for i, route := range routes {
		if route.Redirect != "" {
			code := route.RedirectCode
			if code == 0 {
				code = http.StatusFound
			}
			if route.RedirectTo != nil {
				out[i] = fmt.Sprintf("%s -> %d %s (%s://:%s)", route.Path, code, route.Redirect, route.RedirectTo.Scheme, route.RedirectTo.Port)
				continue
			}
			out[i] = fmt.Sprintf("%s -> %d %s", route.Path, code, route.Redirect)
			continue
		}
		out[i] = route.Path + " -> " + route.Backend
	}
	return out
}

type readyListener struct {
	net.Listener
	conns  chan net.Conn
	ctx    context.Context
	cancel context.CancelFunc
}

func newReadyListener(ctx context.Context, inner net.Listener, cfg *tls.Config) *readyListener {
	ctx, cancel := context.WithCancel(ctx)
	ln := &readyListener{
		Listener: inner,
		conns:    make(chan net.Conn),
		ctx:      ctx,
		cancel:   cancel,
	}
	go ln.accept(cfg)
	return ln
}

func (l *readyListener) accept(cfg *tls.Config) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return
		}
		go l.handshake(conn, cfg)
	}
}

func (l *readyListener) handshake(conn net.Conn, cfg *tls.Config) {
	setNoDelay(conn)
	tlsConn := tls.Server(conn, cfg)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	err := tlsConn.Handshake()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}
	if tlsConn.ConnectionState().NegotiatedProtocol == "acme-tls/1" {
		_ = conn.Close()
		return
	}
	select {
	case l.conns <- tlsConn:
	case <-l.ctx.Done():
		_ = conn.Close()
	}
}

func (l *readyListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *readyListener) Close() error {
	l.cancel()
	err := l.Listener.Close()
	return err
}

func (l *readyListener) Addr() net.Addr {
	return l.Listener.Addr()
}

// tlsRecordHandshake 是 TLS 记录的握手类型。明文 HTTP 的方法名不会以这个字节开头。
const tlsRecordHandshake = 0x16

type sharedBase struct {
	ln   net.Listener
	once sync.Once
	err  error
}

func (b *sharedBase) Close() error {
	b.once.Do(func() {
		b.err = b.ln.Close()
	})
	return b.err
}

type chanListener struct {
	addr   net.Addr
	conns  chan net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	base   *sharedBase
	once   sync.Once
}

func newChanListener(ctx context.Context, addr net.Addr, base *sharedBase) *chanListener {
	ctx, cancel := context.WithCancel(ctx)
	return &chanListener{
		addr:   addr,
		conns:  make(chan net.Conn),
		ctx:    ctx,
		cancel: cancel,
		base:   base,
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() {
		l.cancel()
	})
	return l.base.Close()
}

func (l *chanListener) Addr() net.Addr { return l.addr }

type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func newSplitListeners(ctx context.Context, ln net.Listener) (plain, tls net.Listener) {
	base := &sharedBase{ln: ln}
	plainLn := newChanListener(ctx, ln.Addr(), base)
	tlsLn := newChanListener(ctx, ln.Addr(), base)
	go func() {
		<-ctx.Done()
		_ = base.Close()
	}()
	go acceptSplit(ctx, ln, plainLn, tlsLn)
	return plainLn, tlsLn
}

func acceptSplit(ctx context.Context, ln net.Listener, plain, tls *chanListener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go dispatchSplit(ctx, conn, plain, tls)
	}
}

func dispatchSplit(ctx context.Context, conn net.Conn, plain, tls *chanListener) {
	setNoDelay(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(3)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}
	wrapped := &prefixConn{Conn: conn, r: reader}
	dest := plain.conns
	if first[0] == tlsRecordHandshake && first[1] == 0x03 {
		dest = tls.conns
	}
	select {
	case dest <- wrapped:
	case <-ctx.Done():
		_ = conn.Close()
	}
}
