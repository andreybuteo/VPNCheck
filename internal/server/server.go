// Package server exposes the local HTTP API and the embedded UI on 127.0.0.1.
//
// Security model (spec §7):
//   - The listener binds to loopback only.
//   - The browser is opened with a one-time launch URL carrying a random token.
//     Presenting it sets an HttpOnly, SameSite=Strict session cookie.
//   - Every /api request requires the session cookie; mutating requests
//     additionally require the X-VPNCheck-CSRF header obtained from GET /api/session.
//   - Host, Origin and Sec-Fetch-Site are validated, so a foreign web page cannot
//     start a run, read history or shut the application down. No CORS is emitted.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/i18n"
)

const (
	cookieName = "vpncheck_session"
	csrfHeader = "X-VPNCheck-CSRF"
)

// Config configures the server.
type Config struct {
	// UI is the embedded static file system (index.html at root).
	UI fs.FS
	// Port is 0 for a free port.
	Port int
	// OnQuit is invoked after POST /api/quit has been answered.
	OnQuit func()
	// Logger receives diagnostic lines; nil disables logging.
	Logger *log.Logger
}

// Server is the local API server.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	api     *http.ServeMux
	ln      net.Listener
	httpSrv *http.Server
	hub     *Hub

	launchToken string
	session     string
	csrf        string

	hostsMu      sync.RWMutex
	allowedHosts map[string]struct{}
	quitOnce     sync.Once
}

// New creates a server. Call Listen before Serve.
func New(cfg Config) (*Server, error) {
	if cfg.UI == nil {
		return nil, errors.New("server: UI file system is required")
	}
	s := &Server{
		cfg:          cfg,
		mux:          http.NewServeMux(),
		api:          http.NewServeMux(),
		hub:          NewHub(),
		launchToken:  randomToken(),
		session:      randomToken(),
		csrf:         randomToken(),
		allowedHosts: map[string]struct{}{},
	}
	s.routes()
	return s, nil
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Hub returns the SSE hub for publishing progress events.
func (s *Server) Hub() *Hub { return s.hub }

// LaunchToken is the one-time token used to establish the browser session.
func (s *Server) LaunchToken() string { return s.launchToken }

// Listen binds 127.0.0.1 on the configured port.
func (s *Server) Listen() error {
	addr := net.JoinHostPort("127.0.0.1", itoa(s.cfg.Port))
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	port := ln.Addr().(*net.TCPAddr).Port
	s.hostsMu.Lock()
	s.allowedHosts = map[string]struct{}{
		"127.0.0.1:" + itoa(port): {},
		"localhost:" + itoa(port): {},
	}
	s.hostsMu.Unlock()
	s.httpSrv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		ErrorLog:          s.cfg.Logger,
	}
	return nil
}

// Port returns the bound port (0 before Listen).
func (s *Server) Port() int {
	if s.ln == nil {
		return 0
	}
	return s.ln.Addr().(*net.TCPAddr).Port
}

// BaseURL returns http://127.0.0.1:port.
func (s *Server) BaseURL() string {
	return "http://127.0.0.1:" + itoa(s.Port())
}

// LaunchURL returns the URL that establishes the browser session.
func (s *Server) LaunchURL() string {
	return s.BaseURL() + "/session?t=" + s.launchToken
}

// Serve blocks until the server is shut down.
func (s *Server) Serve() error {
	if s.ln == nil {
		return errors.New("server: Listen was not called")
	}
	err := s.httpSrv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops the server gracefully and releases the port.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// HandleAPI registers an authenticated API handler. pattern uses ServeMux
// syntax with a method, e.g. "GET /api/state". Mutating methods automatically
// require the CSRF header.
func (s *Server) HandleAPI(pattern string, h http.HandlerFunc) {
	s.api.HandleFunc(pattern, h)
}

// Handler returns the root handler (used directly in tests).
func (s *Server) Handler() http.Handler {
	return s.secure(s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /session", s.handleSession)
	s.mux.Handle("/api/", s.requireSession(s.api))
	s.api.HandleFunc("GET /api/session", s.handleSessionInfo)
	s.api.HandleFunc("GET /api/events", s.hub.ServeHTTP)
	s.api.HandleFunc("POST /api/quit", s.handleQuit)
	s.api.HandleFunc("GET /api/ping", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC()})
	})
	s.mux.HandleFunc("GET /api/instance", s.handleInstance) // unauthenticated, minimal
	s.mux.Handle("/", s.staticHandler())
}

// secure applies Host/Origin/Sec-Fetch-Site checks and security headers to everything.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

		if !s.hostAllowed(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
			if !strings.EqualFold(origin, "http://"+r.Host) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		} else if origin == "null" {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "forbidden fetch site", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodOptions {
			// No CORS preflight support: nothing but same-origin is allowed.
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(host string) bool {
	s.hostsMu.RLock()
	defer s.hostsMu.RUnlock()
	if len(s.allowedHosts) == 0 {
		return false
	}
	_, ok := s.allowedHosts[strings.ToLower(host)]
	return ok
}

// requireSession checks the cookie and, for mutating methods, the CSRF header.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.session)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":   "session_required",
				"message": i18n.T("Сессия не найдена. Запустите VPNCheck.exe ещё раз: он откроет интерфейс с действующей сессией."),
			})
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(s.csrf)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "csrf_required"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// handleSession exchanges the launch token for the session cookie.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	if subtle.ConstantTimeCompare([]byte(t), []byte(s.launchToken)) != 1 {
		http.Error(w, "invalid launch token", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    s.session,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure is deliberately off: loopback http only.
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleSessionInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"csrf":    s.csrf,
		"app":     app.Name,
		"version": app.Version,
	})
}

func (s *Server) handleInstance(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("X-VPNCheck-Instance", app.Name)
	writeJSON(w, http.StatusOK, map[string]any{"app": app.Name, "version": app.Version})
}

func (s *Server) handleQuit(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": i18n.T("Приложение завершается.")})
	s.quitOnce.Do(func() {
		if s.cfg.OnQuit != nil {
			go s.cfg.OnQuit()
		}
	})
}

func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServerFS(s.cfg.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.cfg.UI, p); err != nil {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
