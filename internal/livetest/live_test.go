//go:build live

package livetest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Solyzon/privacy-gateway/internal/gateway"
)

const gitlabToken = "glpat-" + "Tq3vX9mLp2Rw7Kz4Nb8E"

var secrets = []string{"Tr0ub4dor&3-horse", gitlabToken, "camille.durand@orange.fr"}

const env = "APP_ENV=production\nDB_PASSWORD=Tr0ub4dor&3-horse\nGITLAB_TOKEN=" + gitlabToken + "\nSUPPORT_CONTACT=camille.durand@orange.fr\n"

type recorder struct {
	mu        sync.Mutex
	requests  []string
	responses []string
	headers   []http.Header
	usage     []map[string]any
}

func (r *recorder) start(t *testing.T, upstream string) *httptest.Server {
	target, _ := url.Parse(upstream)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		req.Host = target.Host
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		r.mu.Lock()
		r.responses = append(r.responses, string(raw))
		r.mu.Unlock()
		if resp.Request.URL.Path == "/v1/messages" {
			for _, line := range strings.Split(string(raw), "\n") {
				var ev struct {
					Type    string `json:"type"`
					Message struct {
						Model string         `json:"model"`
						Usage map[string]any `json:"usage"`
					} `json:"message"`
				}
				if strings.HasPrefix(line, "data: ") && json.Unmarshal([]byte(line[6:]), &ev) == nil && ev.Type == "message_start" {
					ev.Message.Usage["model"] = ev.Message.Model
					r.mu.Lock()
					r.usage = append(r.usage, ev.Message.Usage)
					r.mu.Unlock()
				}
			}
		}
		return err
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(b))
		r.mu.Lock()
		r.requests = append(r.requests, req.URL.Path+" "+string(b))
		r.headers = append(r.headers, req.Header.Clone())
		r.mu.Unlock()
		proxy.ServeHTTP(w, req)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func startGateway(t *testing.T, upstream, home string) *httptest.Server {
	g, err := gateway.New(gateway.Config{Upstream: upstream, Home: home, Version: "live"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g)
	return srv
}

type result struct {
	SessionID string `json:"session_id"`
	Result    string `json:"result"`
	IsError   bool   `json:"is_error"`
}

func claude(t *testing.T, dir, base, prompt string, args ...string) result {
	cmd := exec.Command("claude", append([]string{"-p", "--model", "haiku", "--output-format", "json", "--setting-sources", "project", "--strict-mcp-config",
		"--allowedTools", "Read,Write,Edit,Bash(python3:*),Bash(cat:*),Bash(ls:*)"}, args...)...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Env = append(os.Environ(), "ANTHROPIC_BASE_URL="+base, "MAX_THINKING_TOKENS=2048")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	out, err := cmd.Output()
	t.Logf("claude %q in %s", prompt[:min(40, len(prompt))], time.Since(start).Round(time.Second))
	var r result
	if err != nil || json.Unmarshal(out, &r) != nil || r.IsError {
		t.Fatalf("claude failed: %v %s %s", err, out, stderr.String())
	}
	return r
}

func checkUpstream(t *testing.T, rec *recorder) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, body := range rec.requests {
		for _, s := range secrets {
			if strings.Contains(body, s) {
				i := strings.Index(body, s)
				t.Errorf("%q reached Anthropic: ...%s...", s, body[max(0, i-400):min(len(body), i+100)])
			}
		}
	}
}

func statuses(t *testing.T, home string) map[int]int {
	raw, _ := os.ReadFile(filepath.Join(home, "status.log"))
	out := map[int]int{}
	var ms []float64
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e struct {
			Path   string  `json:"path"`
			Status int     `json:"status"`
			MaskMs float64 `json:"mask_ms"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && (strings.HasPrefix(e.Path, "/v1/messages") || strings.HasSuffix(e.Path, "/responses")) {
			out[e.Status]++
			ms = append(ms, e.MaskMs)
		}
	}
	sort.Float64s(ms)
	if len(ms) > 0 {
		t.Logf("masking time per request: median %.2f ms, max %.2f ms over %d requests", ms[len(ms)/2], ms[len(ms)-1], len(ms))
	}
	return out
}

func TestLiveClaudeCode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600)
	home := t.TempDir()
	rec := &recorder{}
	up := rec.start(t, "https://api.anthropic.com")

	gw := startGateway(t, up.URL, home)
	first := claude(t, dir, gw.URL, "Lis le fichier .env. Puis écris config.py qui définit DB_PASSWORD, GITLAB_TOKEN et SUPPORT_CONTACT comme constantes Python avec exactement les valeurs du .env. Puis lance python3 -c \"import config; print(len(config.DB_PASSWORD))\" et dis-moi le résultat. Puis relis config.py pour vérifier.")
	gw.Close()

	config, err := os.ReadFile(filepath.Join(dir, "config.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if !strings.Contains(string(config), s) {
			t.Errorf("config.py lacks the real value %q:\n%s", s, config)
		}
	}

	gw = startGateway(t, up.URL, home)
	defer gw.Close()
	second := claude(t, dir, gw.URL, "Quelle est la valeur exacte de DB_PASSWORD ? Réponds seulement la valeur.", "--resume", first.SessionID)
	if !strings.Contains(second.Result, "Tr0ub4dor&3-horse") {
		t.Errorf("answer after restart lacks the real value: %q", second.Result)
	}

	checkUpstream(t, rec)
	st := statuses(t, home)
	t.Logf("statuses %v", st)
	for code, n := range st {
		if code != 200 {
			t.Errorf("%d answers with status %d", n, code)
		}
	}
	rec.mu.Lock()
	cached := 0
	for _, u := range rec.usage {
		if v, _ := u["cache_read_input_tokens"].(float64); v > 0 {
			cached++
		}
	}
	t.Logf("%d of %d message answers read the prompt cache: %v", cached, len(rec.usage), rec.usage)
	if cached == 0 {
		t.Error("the prompt cache never hit")
	}
	for _, h := range rec.headers {
		for k := range h {
			if strings.Contains(strings.ToLower(k), "session") {
				t.Logf("session header %s", k)
			}
		}
		break
	}
	rec.mu.Unlock()
	if _, err := os.Stat(filepath.Join(home, "sessions", first.SessionID+".json")); err != nil {
		t.Errorf("no masking notice for session %s: %v", first.SessionID, err)
	}
}

func TestLiveCodex(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "settings.txt"), []byte(env), 0o600)
	home := t.TempDir()
	rec := &recorder{}
	up := rec.start(t, "https://chatgpt.com/backend-api/codex")
	g, err := gateway.New(gateway.Config{Upstream: "http://127.0.0.1:1", ChatGPT: up.URL, Home: home, Version: "live"})
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(g)
	defer gw.Close()
	args := []string{"exec", "--skip-git-repo-check", "--ephemeral", "-s", "workspace-write",
		"-c", "model_provider=pgw",
		"-c", `model_providers.pgw={name="pgw",base_url="` + gw.URL + `/codex",wire_api="responses",requires_openai_auth=true}`,
		"Lis settings.txt. Puis écris config.py qui définit DB_PASSWORD, GITLAB_TOKEN et SUPPORT_CONTACT comme constantes Python avec exactement les valeurs du fichier. Puis lance python3 -c \"import config; print(len(config.DB_PASSWORD))\" et donne le résultat."}
	name := "codex"
	if _, err := exec.LookPath("codex"); err != nil {
		name, args = "npx", append([]string{"-y", "@openai/codex@latest"}, args...)
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	start := time.Now()
	out, err := cmd.CombinedOutput()
	t.Logf("codex in %s", time.Since(start).Round(time.Second))
	if err != nil {
		t.Fatalf("codex failed: %v %s", err, out[max(0, len(out)-2000):])
	}
	config, err := os.ReadFile(filepath.Join(dir, "config.py"))
	if err != nil {
		t.Fatalf("no config.py: %s", out[max(0, len(out)-2000):])
	}
	for _, s := range secrets {
		if !strings.Contains(string(config), s) {
			t.Errorf("config.py lacks the real value %q:\n%s\n%s", s, config, out[max(0, len(out)-1500):])
		}
	}
	checkUpstream(t, rec)
	rec.mu.Lock()
	t.Logf("%d requests reached the provider", len(rec.requests))
	if dump := os.Getenv("PGW_LIVE_DUMP"); dump != "" {
		os.MkdirAll(dump, 0o700)
		for i, b := range rec.requests {
			os.WriteFile(filepath.Join(dump, fmt.Sprintf("req-%d.txt", i)), []byte(b), 0o600)
		}
		for i, b := range rec.responses {
			os.WriteFile(filepath.Join(dump, fmt.Sprintf("resp-%d.txt", i)), []byte(b), 0o600)
		}
	}
	rec.mu.Unlock()
	t.Logf("statuses %v", statuses(t, home))
}
