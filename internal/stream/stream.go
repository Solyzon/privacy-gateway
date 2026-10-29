package stream

import (
	"bytes"
	"encoding/json"
	"regexp"

	"github.com/Solyzon/privacy-gateway/internal/mask"
)

var partial = regexp.MustCompile(`S(?:Z(?:_(?:[A-Z]+(?:_[0-9a-f]{0,11})?)?)?)?$`)

var fields = map[string]string{"text_delta": "text", "input_json_delta": "partial_json"}

type held struct {
	text, kind string
}

type Unmasker struct {
	table   *mask.Table
	pending map[int]held
}

func New(table *mask.Table) *Unmasker {
	return &Unmasker{table: table, pending: map[int]held{}}
}

type event struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

func (u *Unmasker) unmask(kind, s string) string {
	if kind == "input_json_delta" {
		return u.table.UnmaskJSON(s)
	}
	return u.table.Unmask(s)
}

func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func deltaEvent(index int, kind, value string) []byte {
	payload := marshal(map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]string{"type": kind, fields[kind]: value}})
	return append([]byte("event: content_block_delta\ndata: "), payload...)
}

func (u *Unmasker) Event(ev []byte) []byte {
	lines := bytes.Split(ev, []byte("\n"))
	at := -1
	for i, l := range lines {
		if bytes.HasPrefix(l, []byte("data: ")) {
			at = i
			break
		}
	}
	if at < 0 {
		return ev
	}
	var e event
	if json.Unmarshal(lines[at][6:], &e) != nil {
		return ev
	}
	switch e.Type {
	case "content_block_delta":
		field, ok := fields[e.Delta.Type]
		if !ok {
			return ev
		}
		value := e.Delta.Text
		if field == "partial_json" {
			value = e.Delta.PartialJSON
		}
		before := u.pending[e.Index]
		s := before.text + value
		cut := len(s)
		if loc := partial.FindStringIndex(s); loc != nil {
			cut = loc[0]
		}
		out := u.unmask(e.Delta.Type, s[:cut])
		if cut < len(s) {
			u.pending[e.Index] = held{text: s[cut:], kind: e.Delta.Type}
		} else {
			delete(u.pending, e.Index)
		}
		if before.text == "" && out == value {
			return ev
		}
		var raw map[string]any
		dec := json.NewDecoder(bytes.NewReader(lines[at][6:]))
		dec.UseNumber()
		dec.Decode(&raw)
		raw["delta"].(map[string]any)[field] = out
		lines[at] = append([]byte("data: "), marshal(raw)...)
		return bytes.Join(lines, []byte("\n"))
	case "content_block_stop":
		rest, ok := u.pending[e.Index]
		if !ok {
			return ev
		}
		delete(u.pending, e.Index)
		flush := deltaEvent(e.Index, rest.kind, u.unmask(rest.kind, rest.text))
		return append(append(flush, '\n', '\n'), ev...)
	}
	return ev
}
