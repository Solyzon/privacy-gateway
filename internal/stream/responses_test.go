package stream

import (
	"encoding/json"
	"strings"
	"testing"
)

func responsesSetup(t *testing.T) (*Responses, string) {
	u, token := setup(t)
	return NewResponses(u.table), token
}

func sse(v map[string]any) []byte {
	b, _ := json.Marshal(v)
	return []byte("event: " + v["type"].(string) + "\ndata: " + string(b))
}

func deltas(t *testing.T, u *Responses, events ...[]byte) (string, []map[string]any) {
	var text strings.Builder
	var all []map[string]any
	for _, ev := range events {
		for _, e := range strings.Split(string(u.Event(ev)), "\n\n") {
			for _, line := range strings.Split(e, "\n") {
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				var d map[string]any
				if err := json.Unmarshal([]byte(line[6:]), &d); err != nil {
					t.Fatalf("invalid event %q", line)
				}
				all = append(all, d)
				if s, ok := d["delta"].(string); ok {
					text.WriteString(s)
				}
			}
		}
	}
	return text.String(), all
}

func TestResponsesTextSplitPlaceholder(t *testing.T) {
	u, token := responsesSetup(t)
	text, all := deltas(t, u,
		sse(map[string]any{"type": "response.output_item.added", "item": map[string]any{"type": "message", "id": "msg_1"}}),
		sse(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "mot " + token[:6], "obfuscation": "x"}),
		sse(map[string]any{"type": "response.output_text.delta", "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": token[6:] + " fin"}),
		sse(map[string]any{"type": "response.output_text.done", "item_id": "msg_1", "output_index": 0, "content_index": 0, "text": "mot " + token + " fin"}))
	if text != "mot "+secret+" fin" {
		t.Fatalf("deltas %q", text)
	}
	if done := all[len(all)-1]["text"]; done != "mot "+secret+" fin" {
		t.Fatalf("done text %q", done)
	}
}

func TestResponsesToolInputIsEscaped(t *testing.T) {
	u, token := responsesSetup(t)
	text, all := deltas(t, u,
		sse(map[string]any{"type": "response.output_item.added", "item": map[string]any{"type": "custom_tool_call", "id": "ctc_1", "name": "exec"}}),
		sse(map[string]any{"type": "response.custom_tool_call_input.delta", "item_id": "ctc_1", "output_index": 1, "delta": `tools.exec_command({"cmd":"psql -W ` + token[:3]}),
		sse(map[string]any{"type": "response.custom_tool_call_input.delta", "item_id": "ctc_1", "output_index": 1, "delta": token[3:] + `"})`}),
		sse(map[string]any{"type": "response.custom_tool_call_input.done", "item_id": "ctc_1", "output_index": 1, "input": `tools.exec_command({"cmd":"psql -W ` + token + `"})`}),
		sse(map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "custom_tool_call", "id": "ctc_1", "name": "exec", "call_id": "call_1", "input": `tools.exec_command({"cmd":"psql -W ` + token + `"})`}}))
	escaped := strings.ReplaceAll(secret, `"`, `\"`)
	if text != `tools.exec_command({"cmd":"psql -W `+escaped+`"})` {
		t.Fatalf("deltas %q", text)
	}
	item := all[len(all)-1]["item"].(map[string]any)
	if item["input"] != `tools.exec_command({"cmd":"psql -W `+escaped+`"})` || item["call_id"] != "call_1" {
		t.Fatalf("item %v", item)
	}
}

func TestResponsesPatchIsRaw(t *testing.T) {
	u, token := responsesSetup(t)
	_, all := deltas(t, u,
		sse(map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "custom_tool_call", "id": "ctc_2", "name": "apply_patch", "input": "*** Begin Patch\n+PASSWORD=" + token + "\n*** End Patch"}}))
	if all[0]["item"].(map[string]any)["input"] != "*** Begin Patch\n+PASSWORD="+secret+"\n*** End Patch" {
		t.Fatalf("got %v", all[0])
	}
}

func TestResponsesReasoningUntouched(t *testing.T) {
	u, token := responsesSetup(t)
	ev := sse(map[string]any{"type": "response.output_item.done", "item": map[string]any{"type": "reasoning", "id": "rs_1", "encrypted_content": token}})
	if got := u.Event(ev); string(got) != string(ev) {
		t.Fatalf("reasoning changed: %s", got)
	}
}
