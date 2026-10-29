package stream

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Solyzon/privacy-gateway/internal/mask"
)

const secret = `Tr0ub4"dor&3-horse`

func setup(t *testing.T) (*Unmasker, string) {
	m := mask.New([]byte("0123456789abcdef0123456789abcdef"))
	table := m.NewTable()
	table.Learn("x://u:" + secret + "@h")
	token := table.Entries()[0].Token
	return New(table), token
}

func delta(index int, kind, field, value string) string {
	b, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]string{"type": kind, field: value}})
	return "event: content_block_delta\ndata: " + string(b)
}

func collect(t *testing.T, u *Unmasker, field string, events ...string) string {
	var out strings.Builder
	for _, ev := range events {
		for _, e := range strings.Split(string(u.Event([]byte(ev))), "\n\n") {
			for _, line := range strings.Split(e, "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var d struct {
					Type  string            `json:"type"`
					Delta map[string]string `json:"delta"`
				}
				if err := json.Unmarshal([]byte(line[6:]), &d); err != nil {
					t.Fatalf("invalid event %q: %v", line, err)
				}
				out.WriteString(d.Delta[field])
			}
		}
	}
	return out.String()
}

func TestSplitPlaceholder(t *testing.T) {
	u, token := setup(t)
	text := collect(t, u, "text",
		delta(0, "text_delta", "text", "le mot de passe est "+token[:2]),
		delta(0, "text_delta", "text", token[2:9]),
		delta(0, "text_delta", "text", token[9:]+" voilà"),
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}")
	if text != "le mot de passe est "+secret+" voilà" {
		t.Fatalf("got %q", text)
	}
}

func TestToolInputIsUnmaskedAsJSON(t *testing.T) {
	u, token := setup(t)
	partial := collect(t, u, "partial_json",
		delta(1, "input_json_delta", "partial_json", `{"command": "psql -W `+token[:5]),
		delta(1, "input_json_delta", "partial_json", token[5:]+`"}`))
	var input map[string]string
	if err := json.Unmarshal([]byte(partial), &input); err != nil || input["command"] != "psql -W "+secret {
		t.Fatalf("got %q %v", partial, err)
	}
}

func TestRestIsFlushedAtBlockStop(t *testing.T) {
	u, _ := setup(t)
	text := collect(t, u, "text",
		delta(0, "text_delta", "text", "fin S"),
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}")
	if text != "fin S" {
		t.Fatalf("got %q", text)
	}
}

func TestOtherEventsAreUntouched(t *testing.T) {
	u, token := setup(t)
	for _, ev := range []string{
		delta(0, "thinking_delta", "thinking", token),
		delta(0, "signature_delta", "signature", "abc"),
		"event: ping\ndata: {\"type\": \"ping\"}",
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\"}}",
		": keepalive",
	} {
		if got := string(u.Event([]byte(ev))); got != ev {
			t.Errorf("event changed:\n%s\n%s", ev, got)
		}
	}
}

func TestPlainDeltaKeepsItsBytes(t *testing.T) {
	u, _ := setup(t)
	ev := `event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"bonjour"}}`
	if got := string(u.Event([]byte(ev))); got != ev {
		t.Fatalf("got %s", got)
	}
}
