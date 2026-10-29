package body

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Solyzon/privacy-gateway/internal/mask"
)

const secret = "Tr0ub4dor&3-horse"

var request = `{
  "model": "claude-haiku-4-5",
  "system": [{"type": "text", "text": "Tu es un agent.", "cache_control": {"type": "ephemeral"}}],
  "metadata": {"user_id": "user_ab_account_cd_session_0b9e"},
  "messages": [
    {"role": "user", "content": "Lis le .env"},
    {"role": "assistant", "content": [
      {"type": "thinking", "thinking": "DB_PASSWORD=` + secret + `", "signature": "c2lnbmF0dXJl"},
      {"type": "tool_use", "id": "toolu_01", "name": "Bash", "input": {"zeta": 1, "command": "cat .env", "alpha": "psql -W ` + secret + `"}}
    ]},
    {"role": "user", "content": [
      {"type": "tool_result", "tool_use_id": "toolu_01", "content": "DB_PASSWORD=` + secret + `\nMAIL=camille.durand@orange.fr\n"},
      {"type": "tool_result", "tool_use_id": "toolu_02", "content": [{"type": "text", "text": "contact : camille.durand@orange.fr"}]},
      {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AKIAZ7QX3M9P2LK4RT8W"}},
      {"type": "text", "text": "café   <b>"}
    ]}
  ]
}`

func masker() *mask.Masker { return mask.New([]byte("0123456789abcdef0123456789abcdef")) }

func TestMaskRequest(t *testing.T) {
	out, table, err := MaskRequest([]byte(request), masker())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !json.Valid(out) {
		t.Fatalf("invalid JSON: %s", s)
	}
	if strings.Count(s, secret) != 1 || !strings.Contains(s, `"thinking": "DB_PASSWORD=`+secret) {
		t.Fatalf("secret left outside the thinking block or thinking changed: %s", s)
	}
	if strings.Contains(s, "camille.durand@orange.fr") {
		t.Fatalf("e-mail left in clear: %s", s)
	}
	for _, kept := range []string{`"signature": "c2lnbmF0dXJl"`, `"id": "toolu_01"`, `"tool_use_id": "toolu_01"`, `"model": "claude-haiku-4-5"`, `"data": "AKIAZ7QX3M9P2LK4RT8W"`, `café   <b>`, `{"zeta": 1, "command": "cat .env", "alpha": "psql -W SZ_SECRET_`} {
		if !strings.Contains(s, kept) {
			t.Errorf("%q should be untouched in %s", kept, s)
		}
	}
	if len(table.Entries()) != 2 {
		t.Fatalf("expected two values, got %+v", table.Entries())
	}
}

func TestMaskRequestIsStable(t *testing.T) {
	m := masker()
	a, _, _ := MaskRequest([]byte(request), m)
	b, _, _ := MaskRequest([]byte(request), m)
	c, _, _ := MaskRequest([]byte(request), masker())
	if !bytes.Equal(a, b) || !bytes.Equal(a, c) {
		t.Fatal("the same history is masked differently")
	}
}

func TestUnchangedBodyIsIdentical(t *testing.T) {
	in := `{"model":"m","messages":[{"role":"user","content":"bonjour é"}],"max_tokens":10}`
	out, _, err := MaskRequest([]byte(in), masker())
	if err != nil || string(out) != in {
		t.Fatalf("body rewritten without reason: %s %v", out, err)
	}
}

func TestInvalidJSONIsRefused(t *testing.T) {
	if _, _, err := MaskRequest([]byte(`{"messages": [`), masker()); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestUnmaskResponse(t *testing.T) {
	m := masker()
	_, table, _ := MaskRequest([]byte(request), m)
	var token string
	for _, e := range table.Entries() {
		if e.Kind == mask.Secret {
			token = e.Token
		}
	}
	resp := `{"content":[{"type":"thinking","thinking":"` + token + `","signature":"s"},{"type":"text","text":"mot de passe ` + token + `"}]}`
	out, err := UnmaskResponse([]byte(resp), table)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"content":[{"type":"thinking","thinking":"` + token + `","signature":"s"},{"type":"text","text":"mot de passe ` + secret + `"}]}`
	if string(out) != want {
		t.Fatalf("got %s", out)
	}
}

func TestSessionID(t *testing.T) {
	if got := SessionID([]byte(request)); got != "0b9e" {
		t.Fatalf("got %q", got)
	}
}
