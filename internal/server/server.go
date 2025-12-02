package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"potzure/internal/logging"
	"potzure/internal/store"
)

const (
	maxBodySnippet    = 8 << 20 // 8 MiB body capture window
	maxUploadSize     = 32 << 20
	readHeaderTimeout = 5 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 90 * time.Second
)

// Config wires all server dependencies.
type Config struct {
	Addr         string
	Logger       *logging.Logger
	FileStore    *store.FileStore
	HoneypotID   string
	RateLimit    int
	RateWindow   time.Duration
	TemplatesDir string
}

// Server exposes fake CMS endpoints and logs callers.
type Server struct {
	httpServer *http.Server
	cfg        Config
	limiter    *rateLimiter
	templates  templates
}

// NewServer assembles the HTTP server and routes.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Logger == nil || cfg.FileStore == nil {
		return nil, errors.New("logger and filestore are required")
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 200
	}
	if cfg.RateWindow <= 0 {
		cfg.RateWindow = time.Minute
	}

	tpls, err := loadTemplates(cfg.TemplatesDir)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       cfg,
		limiter:   newRateLimiter(cfg.RateLimit, cfg.RateWindow),
		templates: tpls,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/wp-login.php", s.handleWordPressLogin)
	mux.HandleFunc("/wp-admin/", s.handleWordPressAdmin)
	mux.HandleFunc("/wp-content/plugins/", s.handlePluginIndex)
	mux.HandleFunc("/wp-admin/async-upload.php", s.handleUpload)
	mux.HandleFunc("/administrator/", s.handleJoomlaAdmin)
	mux.HandleFunc("/index.php", s.handleJoomlaComponent)
	mux.HandleFunc("/user/login", s.handleDrupalLogin)
	mux.HandleFunc("/admin/modules", s.handleDrupalModules)
	mux.HandleFunc("/", s.handleDefault)

	var handler http.Handler = mux
	handler = s.rateLimitMiddleware(handler)
	handler = s.loggingMiddleware(handler)

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	return s, nil
}

// ListenAndServe starts the honeypot listener.
func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown attempts a graceful shutdown with timeout.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.httpServer.Shutdown(ctx)
}

// --- Middleware ---

type contextKey string

const (
	ctxExtrasKey contextKey = "extras"
	ctxBodyKey   contextKey = "body"
)

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extras := &eventExtras{}
		ctx := context.WithValue(r.Context(), ctxExtrasKey, extras)

		body := r.Body
		if body == nil {
			body = http.NoBody
		}
		cap := newBodyCapture(body, maxBodySnippet)
		ctx = context.WithValue(ctx, ctxBodyKey, cap)
		r = r.WithContext(ctx)
		r.Body = cap

		recorder := newResponseRecorder(w)
		next.ServeHTTP(recorder, r)

		_ = cap.Close()

		s.logRequest(recorder.status, r, extras)
	})
}

func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.limiter.Allow(ip) {
			extras := getEventExtras(r)
			extras.addMetadata("rate_limited", true)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Handlers ---

func (s *Server) handleWordPressLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		s.logCredentialAttempt(r.Form, r)
		s.captureForm(r)
		time.Sleep(500 * time.Millisecond)
		http.Redirect(w, r, "/wp-login.php?checkemail=confirm", http.StatusFound)
		return
	}

	s.writeHTML(w, s.templates.WordPressLogin)
}

func (s *Server) handleWordPressAdmin(w http.ResponseWriter, r *http.Request) {
	s.writeHTML(w, s.templates.WordPressAdmin)
}

func (s *Server) handlePluginIndex(w http.ResponseWriter, r *http.Request) {
	s.writeHTML(w, s.templates.PluginIndex)
}

func (s *Server) handleJoomlaAdmin(w http.ResponseWriter, r *http.Request) {
	s.writeHTML(w, s.templates.JoomlaAdmin)
}

func (s *Server) handleJoomlaComponent(w http.ResponseWriter, r *http.Request) {
	option := r.URL.Query().Get("option")
	if !strings.HasPrefix(option, "com_") {
		s.handleDefault(w, r)
		return
	}

	s.writeHTML(w, s.templates.JoomlaAdmin)
}

func (s *Server) handleDrupalLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		s.logCredentialAttempt(r.Form, r)
		s.captureForm(r)
		http.Redirect(w, r, "/user/login?destination=/admin", http.StatusFound)
		return
	}

	s.writeHTML(w, s.templates.DrupalLogin)
}

func (s *Server) handleDrupalModules(w http.ResponseWriter, r *http.Request) {
	s.writeHTML(w, s.templates.DrupalModules)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		http.Error(w, "Invalid upload", http.StatusBadRequest)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	s.captureForm(r)

	extras := getEventExtras(r)
	uploadHashes := make(map[string]string)

	for _, files := range r.MultipartForm.File {
		for _, fileHeader := range files {
			file, err := fileHeader.Open()
			if err != nil {
				continue
			}

			saved, err := s.cfg.FileStore.Save(fileHeader.Filename, file)
			file.Close()
			if err != nil {
				extras.addMetadata("upload_error", err.Error())
				continue
			}

			extras.UploadPaths = append(extras.UploadPaths, saved.DiskPath)
			uploadHashes[saved.DiskPath] = saved.Hash
		}
	}

	if len(uploadHashes) > 0 {
		extras.addMetadata("upload_hashes", uploadHashes)
	}

	s.writeHTML(w, []byte("<p>Upload received and queued for processing.</p>"))
}

func (s *Server) handleDefault(w http.ResponseWriter, r *http.Request) {
	s.writeHTML(w, buildPlaceholderPage(r))
}

// --- Helpers ---

func (s *Server) writeHTML(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}

func (s *Server) captureForm(r *http.Request) {
	if len(r.Form) == 0 {
		return
	}
	formCopy := make(map[string][]string, len(r.Form))
	for k, v := range r.Form {
		formCopy[k] = append([]string(nil), v...)
	}
	getEventExtras(r).Form = formCopy
}

func (s *Server) logCredentialAttempt(form map[string][]string, r *http.Request) {
	if len(form) == 0 {
		return
	}
	username := firstFormValue(form, "log", "username", "user", "name", "email")
	password := firstFormValue(form, "pwd", "password", "pass")
	if username == "" && password == "" {
		return
	}
	log.Printf("credential capture uri=%s ip=%s username=%q password=%q", r.RequestURI, clientIP(r), username, password)
}

func firstFormValue(form map[string][]string, keys ...string) string {
	for _, key := range keys {
		if values, ok := form[key]; ok && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func buildPlaceholderPage(r *http.Request) []byte {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	fullPath := path
	if raw := r.URL.RawQuery; raw != "" {
		fullPath = fmt.Sprintf("%s?%s", path, raw)
	}

	hs := sha256.Sum256([]byte(fullPath))
	flavors := []string{
		"Edge module awaiting cache warm-up.",
		"Draft preview locked for concurrent edit.",
		"Integration bridge syncing translations.",
		"Plugin hook paused during maintenance window.",
		"Background worker updating dependency manifest.",
	}
	description := flavors[int(hs[0])%len(flavors)]
	timestamp := time.Now().UTC().Format(time.RFC1123)

	return []byte(fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Maintenance snapshot</title>
  <style>
    body { font-family: sans-serif; background:#f7f8fa; color:#1e1f21; padding:48px; }
    .card { max-width:560px; margin:auto; background:#fff; border:1px solid #dcdfe4; padding:32px; box-shadow:0 1px 3px rgba(15,23,42,0.08); }
    h1 { margin-top:0; font-size:1.4rem; }
    code { background:#f1f5f9; padding:2px 4px; border-radius:4px; }
    .muted { color:#475569; font-size:0.9rem; margin-top:24px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Route placeholder</h1>
    <p><strong>Host:</strong> %s</p>
    <p><strong>Path:</strong> <code>%s</code></p>
    <p>%s</p>
    <p class="muted">Snapshot generated %s</p>
  </div>
</body>
</html>`, html.EscapeString(r.Host), html.EscapeString(fullPath), html.EscapeString(description), html.EscapeString(timestamp)))
}

func (s *Server) logRequest(status int, r *http.Request, extras *eventExtras) {
	bodyHash := ""
	metadata := map[string]interface{}{"status": status}

	if extras != nil && len(extras.Metadata) > 0 {
		for k, v := range extras.Metadata {
			metadata[k] = v
		}
	}

	if capVal, ok := r.Context().Value(ctxBodyKey).(*bodyCapture); ok && capVal != nil {
		bodyHash = capVal.Hash()
		if capVal.Truncated() {
			metadata["body_truncated"] = true
		}
	}

	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		headers[k] = strings.Join(v, "; ")
	}

	evt := logging.Event{
		Timestamp:   time.Now().UTC(),
		SrcIP:       clientIP(r),
		Method:      r.Method,
		URI:         r.RequestURI,
		Headers:     headers,
		UserAgent:   r.UserAgent(),
		BodyHash:    bodyHash,
		Form:        nil,
		UploadPaths: nil,
		Metadata:    metadata,
		HoneypotID:  s.cfg.HoneypotID,
	}

	if extras != nil {
		if len(extras.Form) > 0 {
			evt.Form = extras.Form
		}
		if len(extras.UploadPaths) > 0 {
			evt.UploadPaths = append([]string(nil), extras.UploadPaths...)
		}
	}

	_ = s.cfg.Logger.Log(evt)
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		parts := strings.Split(v, ",")
		return strings.TrimSpace(parts[0])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// --- Templates ---

type templates struct {
	WordPressLogin []byte
	WordPressAdmin []byte
	PluginIndex    []byte
	JoomlaAdmin    []byte
	DrupalLogin    []byte
	DrupalModules  []byte
}

func loadTemplates(dir string) (templates, error) {
	if dir == "" {
		dir = "internal/templates"
	}

	read := func(name string) ([]byte, error) {
		path := filepath.Join(dir, name)
		return os.ReadFile(path)
	}

	wpLogin, err := read("wordpress_login.html")
	if err != nil {
		return templates{}, err
	}
	wpAdmin, err := read("wordpress_admin.html")
	if err != nil {
		return templates{}, err
	}
	plugins, err := read("plugins_index.html")
	if err != nil {
		return templates{}, err
	}
	joomla, err := read("joomla_admin.html")
	if err != nil {
		return templates{}, err
	}
	drupalLogin, err := read("drupal_login.html")
	if err != nil {
		return templates{}, err
	}
	drupalModules, err := read("drupal_modules.html")
	if err != nil {
		return templates{}, err
	}

	return templates{
		WordPressLogin: wpLogin,
		WordPressAdmin: wpAdmin,
		PluginIndex:    plugins,
		JoomlaAdmin:    joomla,
		DrupalLogin:    drupalLogin,
		DrupalModules:  drupalModules,
	}, nil
}

// --- Event extras helpers ---

type eventExtras struct {
	Form        map[string][]string
	UploadPaths []string
	Metadata    map[string]interface{}
}

func getEventExtras(r *http.Request) *eventExtras {
	if extras, ok := r.Context().Value(ctxExtrasKey).(*eventExtras); ok && extras != nil {
		return extras
	}
	return &eventExtras{}
}

func (e *eventExtras) addMetadata(key string, val interface{}) {
	if e == nil {
		return
	}
	if e.Metadata == nil {
		e.Metadata = make(map[string]interface{})
	}
	e.Metadata[key] = val
}

// --- Body capture ---

type bodyCapture struct {
	rc        io.ReadCloser
	hasher    hash.Hash
	limit     int64
	seen      int64
	truncated bool
}

func newBodyCapture(rc io.ReadCloser, limit int64) *bodyCapture {
	if limit <= 0 {
		limit = maxBodySnippet
	}
	return &bodyCapture{
		rc:     rc,
		hasher: sha256.New(),
		limit:  limit,
	}
}

func (b *bodyCapture) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		_, _ = b.hasher.Write(p[:n])
		b.seen += int64(n)
		if b.seen > b.limit {
			b.truncated = true
		}
	}
	return n, err
}

func (b *bodyCapture) Hash() string {
	if b.hasher == nil {
		return ""
	}
	return hex.EncodeToString(b.hasher.Sum(nil))
}

func (b *bodyCapture) Truncated() bool {
	return b.truncated
}

func (b *bodyCapture) Close() error {
	if b.rc == nil {
		return nil
	}
	return b.rc.Close()
}

// --- Rate limiter ---

type rateLimiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	store  map[string]clientWindow
}

type clientWindow struct {
	count int
	start time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:  limit,
		window: window,
		store:  make(map[string]clientWindow),
	}
}

func (r *rateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	window := r.store[ip]
	if now.Sub(window.start) > r.window {
		r.store[ip] = clientWindow{count: 1, start: now}
		return true
	}

	if window.count >= r.limit {
		return false
	}

	window.count++
	r.store[ip] = window
	return true
}

// --- Utilities ---

type responseRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{ResponseWriter: w, status: http.StatusOK}
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(http.StatusOK)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}
