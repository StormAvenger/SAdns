// Package web serves the SAdns browser UI and its JSON API.
//
// Two security models are supported:
//
//   - Desktop (`sadns ui`): loopback-only listener, a one-time token in the
//     launch URL exchanged for an HttpOnly SameSite=Strict cookie, Host-header
//     checks against DNS rebinding, and the token as a CSRF header.
//   - Server (`sadns serve`, Docker/LAN): password login (PBKDF2 hash only),
//     server-side sessions in HttpOnly SameSite=Strict cookies, a per-session
//     CSRF token, Host allow-listing, Origin/Sec-Fetch-Site checks, login rate
//     limiting and request body limits. Unauthenticated access is only
//     possible on a loopback listener and must be requested explicitly.
//
// Both share the same hash-pinned Content-Security-Policy and API.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/StormAvenger/SAdns/internal/auth"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/report"
	"github.com/StormAvenger/SAdns/internal/service"
)

//go:embed index.html
var indexHTML []byte

// cspHeader allows only the exact inline script and stylesheet shipped in
// index.html (by hash) — no other inline code, no remote resources.
var cspHeader = func() string {
	hash := func(open, close string) string {
		i := bytes.Index(indexHTML, []byte(open))
		j := bytes.Index(indexHTML, []byte(close))
		if i < 0 || j < 0 {
			return "'none'"
		}
		body := indexHTML[i+len(open) : j]
		sum := sha256.Sum256(body)
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return "default-src 'none'; script-src " + hash("<script>", "</script>") +
		"; style-src " + hash("<style>", "</style>") +
		"; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

// Mode selects the security model.
type Mode int

const (
	Desktop Mode = iota // loopback + one-time token
	Server              // password + sessions; any listen address
)

// Options configures the UI server.
type Options struct {
	Mode        Mode
	Listen      string // Desktop: loopback only, default 127.0.0.1:0. Server: default :8053
	OpenBrowser bool
	Service     *service.Service
	Tool        model.ToolInfo
	Vantage     model.Vantage
	IdleTimeout time.Duration // Desktop only: exit after this long unused
	Logf        func(format string, a ...any)

	// Server mode.
	Auth          *auth.Manager // required unless NoAuth
	NoAuth        bool          // only permitted on a loopback listener
	AllowedHosts  []string      // extra Host header values; "*" allows any
	SecureCookies bool          // set Secure on cookies (TLS-terminating reverse proxy)
	Ready         func(addr string)
}

type server struct {
	opt    Options
	svc    *service.Service
	token  string // desktop one-time secret
	host   string // listen address
	cookie string
	hostOK map[string]bool
	anyHst bool
	quit   context.CancelFunc

	mu   sync.Mutex
	seen time.Time
}

// ErrNotLoopback is returned when asked to listen on a non-loopback address.
var ErrNotLoopback = errors.New("the desktop UI only listens on loopback addresses (127.0.0.1, ::1, localhost) — use 'sadns serve' (password-protected) for LAN/Docker access, or 'sadns run' for headless reports")

// CheckLoopback validates a listen address.
func CheckLoopback(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", err
	}
	if host == "localhost" || host == "" {
		host = "127.0.0.1"
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.IsLoopback() {
		return "", ErrNotLoopback
	}
	return net.JoinHostPort(a.String(), port), nil
}

func isLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || host == "" {
		return false // ":8053" is every interface
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func newServer(opt Options, listenAddr string) (*server, error) {
	if opt.Service == nil {
		return nil, errors.New("web: no service")
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	s := &server{opt: opt, svc: opt.Service, host: listenAddr, seen: time.Now(), hostOK: map[string]bool{}}
	switch opt.Mode {
	case Desktop:
		var tb [16]byte
		_, _ = rand.Read(tb[:])
		s.token = hex.EncodeToString(tb[:])
		_, port, _ := net.SplitHostPort(listenAddr)
		s.cookie = "sadns_" + port // cookies are not port-scoped; avoid collisions between instances
	case Server:
		if opt.Auth == nil && !opt.NoAuth {
			return nil, errors.New("server mode requires a password (or explicit no-auth on loopback)")
		}
		if opt.NoAuth && !isLoopbackListen(listenAddr) {
			return nil, errors.New("refusing to serve without authentication on a non-loopback address")
		}
		s.cookie = "sadns_session"
		for _, h := range opt.AllowedHosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "*" {
				s.anyHst = true
			} else if h != "" {
				s.hostOK[stripPort(h)] = true
			}
		}
		if hn, err := os.Hostname(); err == nil && hn != "" {
			s.hostOK[strings.ToLower(hn)] = true
		}
	}
	return s, nil
}

// Serve runs the UI until ctx is cancelled (or, in desktop mode, the user
// clicks Quit or the server has been idle for IdleTimeout).
func Serve(ctx context.Context, opt Options) error {
	listen := opt.Listen
	if opt.Mode == Desktop {
		if listen == "" {
			listen = "127.0.0.1:0"
		}
		var err error
		if listen, err = CheckLoopback(listen); err != nil {
			return err
		}
		if opt.IdleTimeout == 0 {
			opt.IdleTimeout = 2 * time.Hour
		}
	} else if listen == "" {
		listen = ":8053"
	}
	if opt.Mode == Server && opt.NoAuth && !isLoopbackListen(listen) {
		return errors.New("refusing to serve without authentication on a non-loopback address")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	s, err := newServer(opt, ln.Addr().String())
	if err != nil {
		ln.Close()
		return err
	}
	opt = s.opt

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.quit = cancel
	hs := &http.Server{Handler: s.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	if opt.Mode == Desktop {
		u := fmt.Sprintf("http://%s/?token=%s", s.host, s.token)
		opt.Logf("SAdns UI running at %s", u)
		opt.Logf("(Keep this window open while you use the UI. Press Ctrl+C or click Quit in the page to stop.)")
		if opt.OpenBrowser {
			if err := openBrowser(u); err != nil {
				opt.Logf("Could not open a browser automatically (%v) — open the URL above manually.", err)
			}
		}
		go s.idleWatch(ctx, cancel)
	} else {
		opt.Logf("SAdns server listening on %s", s.host)
	}
	if opt.Ready != nil {
		opt.Ready(s.host)
	}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = hs.Shutdown(sctx)
	}()
	err = hs.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *server) idleWatch(ctx context.Context, cancel context.CancelFunc) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			idle := s.svc.Current() == nil && time.Since(s.seen) > s.opt.IdleTimeout
			s.mu.Unlock()
			if idle {
				s.opt.Logf("Idle for %s, shutting down.", s.opt.IdleTimeout)
				cancel()
				return
			}
		}
	}
}

func stripPort(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		return hh
	}
	return strings.Trim(h, "[]")
}

// hostAllowed is the DNS-rebinding defence: a browser tricked into sending
// requests to this server under an attacker's domain carries that domain in
// the Host header, which is rejected here.
func (s *server) hostAllowed(host string) bool {
	h := strings.ToLower(stripPort(host))
	if s.opt.Mode == Desktop {
		return h == "127.0.0.1" || h == "localhost" || h == "::1"
	}
	if s.anyHst || h == "localhost" || s.hostOK[h] {
		return true
	}
	_, err := netip.ParseAddr(h)
	return err == nil // IP literals cannot be rebound
}

// sameOrigin rejects cross-site state-changing requests. Browsers send
// Origin on POST/PUT/DELETE; non-browser clients usually send neither header.
func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func secHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

func mutating(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

func (s *server) touch() {
	s.mu.Lock()
	s.seen = time.Now()
	s.mu.Unlock()
}

// handler wraps the API mux with host checks, security headers and auth.
func (s *server) handler() http.Handler {
	api := s.routes()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secHeaders(w)
		if r.URL.Path == "/healthz" {
			api.ServeHTTP(w, r) // liveness only; reveals nothing
			return
		}
		if !s.hostAllowed(r.Host) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Forbidden host %q. If this is a legitimate name for this server, add it to SADNS_ALLOWED_HOSTS (comma-separated).\n", stripPort(r.Host))
			return
		}
		if mutating(r.Method) && !sameOrigin(r) {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		if s.opt.Mode == Desktop {
			s.desktopAuth(api, w, r)
		} else {
			s.serverAuth(api, w, r)
		}
	})
}

func (s *server) validToken(v string) bool {
	return v != "" && subtle.ConstantTimeCompare([]byte(v), []byte(s.token)) == 1
}

// desktopAuth: the page is opened once with ?token=; it then receives an
// HttpOnly SameSite=Strict cookie and the URL is cleaned, so the secret does
// not linger in links, history or downloads. Mutations additionally need the
// secret in a custom header (CSRF).
func (s *server) desktopAuth(api http.Handler, w http.ResponseWriter, r *http.Request) {
	isAPI := strings.HasPrefix(r.URL.Path, "/api/")
	ok, viaQuery := false, false
	if c, err := r.Cookie(s.cookie); err == nil && s.validToken(c.Value) {
		ok = true
	}
	if !ok && !isAPI && r.URL.Path == "/" && s.validToken(r.URL.Query().Get("token")) {
		ok, viaQuery = true, true
	}
	if !ok {
		if !isAPI && r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>SAdns</title><h2>SAdns</h2><p>Open the private link printed in the SAdns console window (it contains a one-time token).</p>`)
			return
		}
		jsonErr(w, http.StatusForbidden, "unauthorised")
		return
	}
	if mutating(r.Method) && !s.validToken(r.Header.Get("X-SAdns-CSRF")) {
		jsonErr(w, http.StatusForbidden, "missing or invalid CSRF header")
		return
	}
	if viaQuery {
		http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	s.touch()
	api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfKey{}, s.token)))
}

type csrfKey struct{}
type sidKey struct{}

// serverAuth: password sessions. The page itself and the login endpoint are
// public; everything else needs a session, and mutations its CSRF token.
func (s *server) serverAuth(api http.Handler, w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/" || path == "/api/v1/login" || path == "/favicon.ico" {
		api.ServeHTTP(w, r)
		return
	}
	if s.opt.NoAuth {
		api.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfKey{}, "")))
		return
	}
	c, err := r.Cookie(s.cookie)
	if err != nil {
		jsonAuthRequired(w)
		return
	}
	csrf, ok := s.opt.Auth.Session(c.Value)
	if !ok {
		jsonAuthRequired(w)
		return
	}
	if mutating(r.Method) && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SAdns-CSRF")), []byte(csrf)) != 1 {
		jsonErr(w, http.StatusForbidden, "missing or invalid CSRF header")
		return
	}
	ctx := context.WithValue(r.Context(), csrfKey{}, csrf)
	ctx = context.WithValue(ctx, sidKey{}, c.Value)
	api.ServeHTTP(w, r.WithContext(ctx))
}

func jsonAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprint(w, `{"error":"login required","auth":"password"}`)
}

// Render produces Markdown or JSON output at the given privacy level.
func Render(rep *model.Report, privacy, format string) []byte {
	cp := *rep
	rd := report.NewRedactor(rep, privacy)
	cp.Privacy = rd.Level()
	var out string
	if format == "json" {
		b, _ := report.JSON(&cp)
		out = string(b)
	} else {
		out = report.Markdown(&cp)
	}
	return []byte(rd.Apply(out))
}

// FileBase is the suggested report file name without extension.
func FileBase(rep *model.Report) string {
	return "sadns-report-" + rep.StartedAt.Format("20060102-150405")
}

func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}
