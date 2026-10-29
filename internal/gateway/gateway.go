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
	"net/http"
	"os"
	"path/filepath"
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
	Home     string
	Version  string
}

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

func masked(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.URL.Path == "/v1/messages" || r.URL.Path == "/v1/messages/count_tokens")
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

	var payload io.Reader = r.Body
	var table *mask.Table
	if masked(r) {
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
		if r.URL.Path == "/v1/messages" {
			g.sessions.notice(body.SessionID(raw), tbl.Entries())
		}
		payload = bytes.NewReader(out)
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, strings.TrimRight(g.cfg.Upstream, "/")+r.URL.RequestURI(), payload)
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
		entry.Status = http.StatusBadGateway
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
	switch {
	case table != nil && strings.HasPrefix(contentType, "text/event-stream"):
		w.WriteHeader(resp.StatusCode)
		relayEvents(w, resp.Body, stream.New(table))
	case table != nil && strings.HasPrefix(contentType, "application/json"):
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			entry.Status = http.StatusBadGateway
			return
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
		copyFlushing(w, resp.Body)
	}
}

func relayEvents(w http.ResponseWriter, r io.Reader, u *stream.Unmasker) {
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
	Time   string         `json:"time"`
	Method string         `json:"method"`
	Path   string         `json:"path"`
	Status int            `json:"status"`
	Ms     int64          `json:"ms"`
	MaskMs float64        `json:"mask_ms"`
	Masked map[string]int `json:"masked,omitempty"`
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
