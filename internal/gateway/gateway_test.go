package gateway

import (
	"context"

	"encoding/json"
	"github.com/Solyzon/privacy-gateway/internal/mask"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const secret = "Tr0ub4dor&3-horse"

type upstream struct {
	mu      sync.Mutex
	bodies  []string
	headers []http.Header
}

var tokenRe = regexp.MustCompile(`SZ_SECRET_[0-9a-f]{12}`)

func (u *upstream) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.bodies = append(u.bodies, string(b))
	u.headers = append(u.headers, r.Header.Clone())
	u.mu.Unlock()
	token := tokenRe.FindString(string(b))
	switch {
	case r.URL.Path == "/v1/messages" && strings.Contains(string(b), `"stream":true`):
		w.Header().Set("Content-Type", "text/event-stream")
		f := w.(http.Flusher)
		for _, part := range []string{"voici " + token[:4], token[4:10], token[10:] + " fin"} {
			d, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": part}})
			io.WriteString(w, "event: content_block_delta\ndata: "+string(d)+"\n\n")
			f.Flush()
		}
		io.WriteString(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	case r.URL.Path == "/v1/messages":
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"`+token+`"}]}`)
	case r.URL.Path == "/v1/messages/count_tokens":
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"input_tokens":12}`)
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte{0x1f, 0x8b, 0x00, 0x01})
	}
}

func start(t *testing.T) (*httptest.Server, *upstream, string) {
	up := &upstream{}
	fake := httptest.NewServer(http.HandlerFunc(up.handler))
	t.Cleanup(fake.Close)
	home := t.TempDir()
	g, err := New(Config{Upstream: fake.URL, Home: home, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return srv, up, home
}

const gitlabToken = "glpat-" + "Tq3vX9mLp2Rw7Kz4Nb8E"

func requestBody(stream bool) string {
	s := "false"
	if stream {
		s = "true"
	}
	return `{"model":"m","stream":` + s + `,"metadata":{"user_id":"user_a_account_b_session_s1"},"messages":[{"role":"user","content":"DB_PASSWORD=` + secret + `\nGITLAB_TOKEN=` + gitlabToken + `\ncamille@orange.fr"}]}`
}

func post(t *testing.T, url, path, payload string) (*http.Response, string) {
	req, _ := http.NewRequest("POST", url+path, strings.NewReader(payload))
	req.Header.Set("anthropic-beta", "interleaved-thinking-2025-05-14")
	req.Header.Set("Authorization", "Bearer sk-ant-oat01-test")
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestStreamIsMaskedAndUnmasked(t *testing.T) {
	srv, up, _ := start(t)
	resp, out := post(t, srv.URL, "/v1/messages?beta=true", requestBody(true))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, out)
	}
	if strings.Contains(up.bodies[0], secret) || strings.Contains(up.bodies[0], "glpat-") || strings.Contains(up.bodies[0], "camille@orange.fr") {
		t.Fatalf("clear value sent upstream: %s", up.bodies[0])
	}
	var text strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "data: ") {
			var d struct {
				Delta struct{ Text string } `json:"delta"`
			}
			json.Unmarshal([]byte(line[6:]), &d)
			text.WriteString(d.Delta.Text)
		}
	}
	if text.String() != "voici "+secret+" fin" {
		t.Fatalf("got %q", text.String())
	}
	if !strings.Contains(up.bodies[0], `"system":[{"type":"text","text":"Values shaped like SZ_`) {
		t.Fatalf("placeholder note missing: %s", up.bodies[0])
	}
	h := up.headers[0]
	if h.Get("anthropic-beta") != "interleaved-thinking-2025-05-14" || h.Get("Authorization") != "Bearer sk-ant-oat01-test" || h.Get("Accept-Encoding") != "identity" {
		t.Fatalf("headers not relayed: %v", h)
	}
}

func TestJSONResponseIsUnmasked(t *testing.T) {
	srv, _, _ := start(t)
	_, out := post(t, srv.URL, "/v1/messages", requestBody(false))
	if out != `{"content":[{"type":"text","text":"`+secret+`"}]}` {
		t.Fatalf("got %s", out)
	}
}

func TestCountTokensIsMasked(t *testing.T) {
	srv, up, _ := start(t)
	post(t, srv.URL, "/v1/messages/count_tokens", requestBody(false))
	if strings.Contains(up.bodies[0], secret) {
		t.Fatal("count_tokens sent in clear")
	}
}

func TestOtherRoutesPassThrough(t *testing.T) {
	srv, up, _ := start(t)
	resp, out := post(t, srv.URL, "/api/other", "DB_PASSWORD="+secret)
	if up.bodies[0] != "DB_PASSWORD="+secret || out != string([]byte{0x1f, 0x8b, 0x00, 0x01}) || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("passthrough changed: %q %q", up.bodies[0], out)
	}
}

func TestInvalidBodyIsBlocked(t *testing.T) {
	srv, up, _ := start(t)
	resp, out := post(t, srv.URL, "/v1/messages", `{"messages":[DB_PASSWORD=`+secret)
	if resp.StatusCode != 400 || len(up.bodies) != 0 || strings.Contains(out, secret) {
		t.Fatalf("invalid body forwarded or echoed: %d %s", resp.StatusCode, out)
	}
}

func TestUpstreamDownGives502(t *testing.T) {
	g, _ := New(Config{Upstream: "http://127.0.0.1:1", Home: t.TempDir(), Version: "test"})
	srv := httptest.NewServer(g)
	defer srv.Close()
	resp, out := post(t, srv.URL, "/v1/messages", requestBody(false))
	if resp.StatusCode != 502 || strings.Contains(out, secret) {
		t.Fatalf("got %d %s", resp.StatusCode, out)
	}
}

func TestHealthz(t *testing.T) {
	srv, _, _ := start(t)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", resp, err)
	}
}

func TestStatusLogHasNoValues(t *testing.T) {
	srv, _, home := start(t)
	post(t, srv.URL, "/v1/messages", requestBody(true))
	log, err := os.ReadFile(filepath.Join(home, "status.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), secret) || strings.Contains(string(log), "camille") || !strings.Contains(string(log), `"status":200`) {
		t.Fatalf("status.log: %s", log)
	}
}

func TestSessionNotice(t *testing.T) {
	srv, _, home := start(t)
	post(t, srv.URL, "/v1/messages", requestBody(true))
	path := filepath.Join(home, "sessions", "s1.json")
	var n struct {
		Time int64  `json:"time"`
		Text string `json:"text"`
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &n) != nil {
		t.Fatalf("notice missing: %v %s", err, b)
	}
	if n.Text != "masqué : DB_PASSWORD, GITLAB_TOKEN, 1 e-mail" || time.Since(time.UnixMilli(n.Time)) > time.Minute || strings.Contains(string(b), secret) {
		t.Fatalf("notice: %s", b)
	}
	os.Remove(path)
	post(t, srv.URL, "/v1/messages", requestBody(true))
	if _, err := os.Stat(path); err == nil {
		t.Fatal("values already announced in this session were announced again")
	}
}

func TestCodexRouteIsMaskedAndUnmasked(t *testing.T) {
	up := &upstream{}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		up.mu.Lock()
		up.bodies = append(up.bodies, r.URL.Path+" "+string(b))
		up.mu.Unlock()
		token := tokenRe.FindString(string(b))
		w.Header()["Content-Type"] = nil
		for _, part := range []string{"cmd " + token[:7], token[7:]} {
			d, _ := json.Marshal(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": part})
			io.WriteString(w, "event: response.output_text.delta\ndata: "+string(d)+"\n\n")
		}
		d, _ := json.Marshal(map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "custom_tool_call", "id": "ctc_1", "name": "exec", "call_id": "c1", "input": "run(\"" + token + "\")"}})
		io.WriteString(w, "event: response.output_item.done\ndata: "+string(d)+"\n\n")
	}))
	defer fake.Close()
	g, _ := New(Config{Upstream: "http://127.0.0.1:1", ChatGPT: fake.URL + "/backend-api/codex", Home: t.TempDir(), Version: "test"})
	srv := httptest.NewServer(g)
	defer srv.Close()
	payload := `{"model":"gpt","stream":true,"prompt_cache_key":"k","input":[{"type":"reasoning","id":"rs_1","encrypted_content":"gAAA"},{"type":"custom_tool_call_output","call_id":"c0","output":[{"type":"input_text","text":"DB_PASSWORD=` + secret + `"}]}]}`
	req, _ := http.NewRequest("POST", srv.URL+"/codex/responses", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(up.bodies[0], "/backend-api/codex/responses ") || strings.Contains(up.bodies[0], secret) || !strings.Contains(up.bodies[0], `"encrypted_content":"gAAA"`) {
		t.Fatalf("upstream got %s", up.bodies[0])
	}
	if !strings.Contains(string(out), `"delta":"`+secret[:2]) || !strings.Contains(string(out), `run(\"`+secret+`\")`) {
		t.Fatalf("answer not unmasked: %s", out)
	}
}

func TestCompressedBodyIsRefused(t *testing.T) {
	srv, up, _ := start(t)
	req, _ := http.NewRequest("POST", srv.URL+"/codex/responses", strings.NewReader("\x28\xb5\x2f\xfd"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType || len(up.bodies) != 0 {
		t.Fatalf("compressed body forwarded: %d", resp.StatusCode)
	}
}

func TestClientCancelIsNotAnUpstreamError(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		<-r.Context().Done()
	}))
	defer slow.Close()
	home := t.TempDir()
	g, _ := New(Config{Upstream: slow.URL, Home: home, Version: "test"})
	srv := httptest.NewServer(g)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/v1/messages", strings.NewReader(requestBody(false)))
	http.DefaultClient.Do(req)
	time.Sleep(200 * time.Millisecond)
	log, _ := os.ReadFile(filepath.Join(home, "status.log"))
	if !strings.Contains(string(log), `"status":499`) {
		t.Fatalf("status.log: %s", log)
	}
}

func TestErrorKindKeepsNoValue(t *testing.T) {
	table := mask.New([]byte("0123456789abcdef0123456789abcdef")).NewTable()
	cases := map[string]string{
		`{"type":"error","error":{"type":"invalid_request_error","message":"messages.12.content.3.thinking.signature: Field required"}}`: "invalid_request_error messages.N.content.N.thinking.signature: Field required",
		`{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 210000 tokens > 200000 maximum"}}`:       "invalid_request_error prompt is too long: N tokens > N maximum",
		`{"error":{"type":"invalid_request_error","message":"unknown user \"SZ_EMAIL_2ec7486cef8e\" or camille@client.fr"}}`:             "invalid_request_error unknown user … or SZ_EMAIL_",
	}
	for in, want := range cases {
		if got := errorKind([]byte(in), table); !strings.HasPrefix(got, want) {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestThreadTurnsUseTheSessionTable(t *testing.T) {
	var mu sync.Mutex
	var last string
	var systems []string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req struct {
			System json.RawMessage `json:"system"`
		}
		json.Unmarshal(b, &req)
		mu.Lock()
		if tok := tokenRe.FindString(string(b)); tok != "" {
			last = tok
		}
		systems = append(systems, string(req.System))
		tok := last
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"content":[{"type":"text","text":"`+tok+`"}]}`)
	}))
	defer fake.Close()
	home := t.TempDir()
	turn := func(content string) string {
		g, err := New(Config{Upstream: fake.URL, Home: home, Version: "test"})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(g)
		defer srv.Close()
		req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(`{"model":"m","thread":{"id":"th_1"},"system":[{"type":"text","text":"S"}],"messages":[{"role":"user","content":`+content+`}]}`))
		req.Header.Set("X-Claude-Code-Session-Id", "3f2a9c1e-0b7d-4e61-9a55-7c1d2e3f4a5b")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(out)
	}
	turn(`"DB_PASSWORD=` + secret + `"`)
	if got := turn(`"quelle valeur ?"`); !strings.Contains(got, secret) {
		t.Fatalf("second turn not unmasked: %s", got)
	}
	if got := turn(`"config = '` + secret + `'"`); !strings.Contains(got, secret) {
		t.Fatalf("third turn not unmasked: %s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range systems {
		if s != systems[0] || !strings.Contains(s, "Values shaped like") {
			t.Fatalf("system changed between turns: %v", systems)
		}
	}
	files, _ := os.ReadDir(filepath.Join(home, "tables"))
	for _, f := range files {
		raw, _ := os.ReadFile(filepath.Join(home, "tables", f.Name()))
		if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "DB_PASSWORD") {
			t.Fatal("session table stored in clear")
		}
	}
	if len(files) != 1 {
		t.Fatalf("expected one session table, got %d", len(files))
	}
}
