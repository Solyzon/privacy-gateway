package gateway

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Solyzon/privacy-gateway/internal/body"
	"github.com/Solyzon/privacy-gateway/internal/mask"
	"github.com/Solyzon/privacy-gateway/internal/stream"
)

const maxBody = 64 << 20

var hopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Host": true,
	"Content-Length": true, "Accept-Encoding": true,
}

type Config struct {
	Upstream string
	ChatGPT  string
	OpenAI   string
	Home     string
	Version  string
}

const (
	anthropicAPI = iota
	responsesAPI
)

type target struct {
	url string
	api int
}

func (g *Gateway) route(r *http.Request) target {
	path := r.URL.Path
	switch {
	case path == "/codex" || strings.HasPrefix(path, "/codex/"):
		return target{url: g.cfg.ChatGPT + strings.TrimPrefix(r.URL.RequestURI(), "/codex"), api: responsesAPI}
	case path == "/openai" || strings.HasPrefix(path, "/openai/"):
		return target{url: g.cfg.OpenAI + strings.TrimPrefix(r.URL.RequestURI(), "/openai"), api: responsesAPI}
	}
	return target{url: g.cfg.Upstream + r.URL.RequestURI(), api: anthropicAPI}
}

func masked(r *http.Request, t target) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if t.api == responsesAPI {
		return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
	}
	return r.URL.Path == "/v1/messages" || r.URL.Path == "/v1/messages/count_tokens"
}

type unmasker interface{ Event([]byte) []byte }

type Gateway struct {
	cfg      Config
	masker   *mask.Masker
	client   *http.Client
	log      *statusLog
	sessions *sessions
	canary   string
}

func LoadKey(home string) ([]byte, error) {
	path := filepath.Join(home, "key")
	key, err := os.ReadFile(path)
	if err == nil && len(key) == 32 {
		return key, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	rand.Read(key)
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	return key, os.WriteFile(path, key, 0o600)
}

func New(cfg Config) (*Gateway, error) {
	key, err := LoadKey(cfg.Home)
	if err != nil {
		return nil, err
	}
	if cfg.ChatGPT == "" {
		cfg.ChatGPT = "https://chatgpt.com/backend-api/codex"
	}
	if cfg.OpenAI == "" {
		cfg.OpenAI = "https://api.openai.com"
	}
	for _, u := range []*string{&cfg.Upstream, &cfg.ChatGPT, &cfg.OpenAI} {
		*u = strings.TrimRight(*u, "/")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = 10 * time.Minute
	canary := make([]byte, 12)
	rand.Read(canary)
	return &Gateway{
		cfg:      cfg,
		masker:   mask.New(key),
		client:   &http.Client{Transport: transport},
		log:      &statusLog{path: filepath.Join(cfg.Home, "status.log")},
		sessions: newSessions(filepath.Join(cfg.Home, "sessions")),
		canary:   hex.EncodeToString(canary),
	}, nil
}

func apiError(w http.ResponseWriter, status int, kind, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": kind, "message": "privacy-gateway: " + message}})
}

func (g *Gateway) healthy() bool {
	payload := `{"messages":[{"role":"user","content":"PRIVACY_GATEWAY_CANARY_TOKEN=` + g.canary + `\n"}]}`
	out, _, err := body.MaskRequest([]byte(payload), g.masker)
	return err == nil && !strings.Contains(string(out), g.canary) && strings.Contains(string(out), "SZ_SECRET_")
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if !g.healthy() {
			http.Error(w, `{"status":"canary leaked"}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`, g.cfg.Version)
		return
	}
	started := time.Now()
	entry := logEntry{Method: r.Method, Path: r.URL.Path}
	defer func() {
		entry.Time = started.UTC().Format(time.RFC3339)
		entry.Ms = time.Since(started).Milliseconds()
		g.log.write(entry)
	}()

	dest := g.route(r)
	var payload io.Reader = r.Body
	var table *mask.Table
	if masked(r, dest) {
		if enc := r.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
			entry.Status = http.StatusUnsupportedMediaType
			apiError(w, entry.Status, "invalid_request_error", "compressed body cannot be inspected, nothing was sent")
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil || len(raw) > maxBody {
			entry.Status = http.StatusRequestEntityTooLarge
			apiError(w, entry.Status, "request_too_large", "body unreadable or over 64 MiB")
			return
		}
		t := time.Now()
		out, tbl, err := body.MaskRequest(raw, g.masker)
		entry.MaskMs = float64(time.Since(t).Microseconds()) / 1000
		if err != nil {
			entry.Status = http.StatusBadRequest
			apiError(w, entry.Status, "invalid_request_error", "body is not valid JSON, nothing was sent")
			return
		}
		table = tbl
		entry.Masked = counts(tbl.Entries())
		for _, f := range body.Attachments(raw) {
			if entry.Unmasked == nil {
				entry.Unmasked = map[string]int{}
			}
			entry.Unmasked[f.Kind]++
		}
		if dest.api == anthropicAPI && len(tbl.Entries()) > 0 {
			if noted, err := body.AddSystemNote(out, body.PlaceholderNote); err == nil {
				out = noted
			}
		}
		if dest.api == anthropicAPI && r.URL.Path == "/v1/messages" {
			g.sessions.notice(body.SessionID(raw), tbl.Entries(), body.Attachments(raw))
		}
		payload = bytes.NewReader(out)
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, dest.url, payload)
	if err != nil {
		entry.Status = http.StatusBadGateway
		apiError(w, entry.Status, "api_error", "bad upstream address")
		return
	}
	for k, v := range r.Header {
		if !hopHeaders[k] {
			req.Header[k] = v
		}
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := g.client.Do(req)
	if err != nil {
		if r.Context().Err() != nil {
			entry.Status = statusClientClosed
			return
		}
		entry.Status = http.StatusBadGateway
		entry.Error = upstreamError(err)
		apiError(w, entry.Status, "api_error", "upstream unreachable")
		return
	}
	defer resp.Body.Close()
	entry.Status = resp.StatusCode
	for k, v := range resp.Header {
		if !hopHeaders[k] {
			w.Header()[k] = v
		}
	}
	contentType := resp.Header.Get("Content-Type")
	src := bufio.NewReaderSize(resp.Body, 64<<10)
	sse := strings.HasPrefix(contentType, "text/event-stream")
	if table != nil && !sse && !strings.HasPrefix(contentType, "application/json") {
		head, _ := src.Peek(6)
		sse = bytes.HasPrefix(head, []byte("event:")) || bytes.HasPrefix(head, []byte("data:"))
	}
	switch {
	case table != nil && sse:
		w.WriteHeader(resp.StatusCode)
		var u unmasker = stream.New(table)
		if dest.api == responsesAPI {
			u = stream.NewResponses(table)
		}
		relayEvents(w, src, u)
	case table != nil && strings.HasPrefix(contentType, "application/json"):
		raw, err := io.ReadAll(src)
		if err != nil {
			entry.Status = http.StatusBadGateway
			return
		}
		if resp.StatusCode >= 400 {
			entry.Error = errorKind(raw)
		}
		if out, err := body.UnmaskResponse(raw, table); err == nil {
			raw = out
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(raw)))
		w.WriteHeader(resp.StatusCode)
		w.Write(raw)
	default:
		if n := resp.Header.Get("Content-Length"); n != "" {
			w.Header().Set("Content-Length", n)
		}
		w.WriteHeader(resp.StatusCode)
		copyFlushing(w, src)
	}
}

func relayEvents(w http.ResponseWriter, r io.Reader, u unmasker) {
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReaderSize(r, 64<<10)
	var event bytes.Buffer
	emit := func() {
		w.Write(u.Event(event.Bytes()))
		w.Write([]byte("\n\n"))
		event.Reset()
		if flusher != nil {
			flusher.Flush()
		}
	}
	for {
		line, err := reader.ReadBytes('\n')
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) > 0 {
			if event.Len() > 0 {
				event.WriteByte('\n')
			}
			event.Write(trimmed)
		} else if len(line) > 0 && event.Len() > 0 {
			emit()
		}
		if err != nil {
			if event.Len() > 0 {
				emit()
			}
			return
		}
	}
}

func copyFlushing(w http.ResponseWriter, r io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func counts(entries []mask.Entry) map[string]int {
	out := map[string]int{}
	for _, e := range entries {
		out[string(e.Kind)]++
	}
	return out
}

type logEntry struct {
	Time     string         `json:"time"`
	Method   string         `json:"method"`
	Path     string         `json:"path"`
	Status   int            `json:"status"`
	Ms       int64          `json:"ms"`
	MaskMs   float64        `json:"mask_ms"`
	Masked   map[string]int `json:"masked,omitempty"`
	Error    string         `json:"error,omitempty"`
	Unmasked map[string]int `json:"unmasked,omitempty"`
}

const statusClientClosed = 499

var errorShape = regexp.MustCompile(`\d+`)

func errorKind(raw []byte) string {
	var e struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return ""
	}
	field := e.Error.Message
	if i := strings.Index(field, ":"); i > 0 && !strings.ContainsAny(field[:i], " \"'") {
		return e.Error.Type + " " + errorShape.ReplaceAllString(field[:i], "N")
	}
	return e.Error.Type
}

func upstreamError(err error) string {
	var dns *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case strings.Contains(err.Error(), "tls"):
		return "tls"
	}
	return "connection"
}

type statusLog struct {
	mu   sync.Mutex
	path string
}

const logLimit = 5 << 20

func (l *statusLog) write(e logEntry) {
	line, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	if info, err := os.Stat(l.path); err == nil && info.Size() > logLimit {
		os.Rename(l.path, l.path+".1")
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}
