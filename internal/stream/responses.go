package stream

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/Solyzon/privacy-gateway/internal/body"
	"github.com/Solyzon/privacy-gateway/internal/mask"
)

type heldDelta struct {
	text, kind  string
	outputIndex int
	content     *int
}

type Responses struct {
	table   *mask.Table
	pending map[string]heldDelta
	order   []string
	items   map[string]bool
}

func NewResponses(table *mask.Table) *Responses {
	return &Responses{table: table, pending: map[string]heldDelta{}, items: map[string]bool{}}
}

type responsesEvent struct {
	Type           string  `json:"type"`
	ItemID         string  `json:"item_id"`
	OutputIndex    int     `json:"output_index"`
	ContentIndex   *int    `json:"content_index"`
	SequenceNumber int     `json:"sequence_number"`
	Delta          *string `json:"delta"`
	Item           *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"item"`
}

func (u *Responses) jsonItem(id string) bool { return u.items[id] }

func (u *Responses) unmask(asJSON bool, s string) string {
	if asJSON {
		return u.table.UnmaskJSON(s)
	}
	return u.table.Unmask(s)
}

func (u *Responses) flush(itemID string, sequence int) []byte {
	var out []byte
	kept := u.order[:0]
	for _, key := range u.order {
		h := u.pending[key]
		if itemID != "" && !strings.HasPrefix(key, itemID+"/") {
			kept = append(kept, key)
			continue
		}
		delete(u.pending, key)
		id := key[:strings.LastIndexByte(key, '/')]
		ev := map[string]any{"type": h.kind, "sequence_number": sequence, "item_id": id, "output_index": h.outputIndex, "delta": u.unmask(u.jsonItem(id), h.text)}
		if h.content != nil {
			ev["content_index"] = *h.content
		}
		out = append(out, "event: "+h.kind+"\ndata: "...)
		out = append(out, marshal(ev)...)
		out = append(out, '\n', '\n')
	}
	u.order = kept
	return out
}

func (u *Responses) Event(ev []byte) []byte {
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
	data := lines[at][6:]
	var e responsesEvent
	if json.Unmarshal(data, &e) != nil {
		return ev
	}
	if e.Type == "response.output_item.added" && e.Item != nil {
		u.items[e.Item.ID] = e.Item.Type == "function_call" || (e.Item.Type == "custom_tool_call" && e.Item.Name != "apply_patch")
	}
	if strings.HasSuffix(e.Type, ".delta") && e.Delta != nil && e.ItemID != "" {
		key := e.ItemID + "/"
		if e.ContentIndex != nil {
			key += string(rune('0' + *e.ContentIndex))
		}
		before, had := u.pending[key]
		s := before.text + *e.Delta
		cut := len(s)
		if loc := partial.FindStringIndex(s); loc != nil {
			cut = loc[0]
		}
		out := u.unmask(u.jsonItem(e.ItemID), s[:cut])
		if cut < len(s) {
			if !had {
				u.order = append(u.order, key)
			}
			u.pending[key] = heldDelta{text: s[cut:], kind: e.Type, outputIndex: e.OutputIndex, content: e.ContentIndex}
		} else if had {
			delete(u.pending, key)
			kept := u.order[:0]
			for _, k := range u.order {
				if k != key {
					kept = append(kept, k)
				}
			}
			u.order = kept
		}
		if !had && out == *e.Delta {
			return ev
		}
		rewritten, err := body.Rewrite(data, func(k, v string) string {
			if k == "delta" {
				return out
			}
			return v
		})
		if err != nil {
			return ev
		}
		lines[at] = append([]byte("data: "), rewritten...)
		return bytes.Join(lines, []byte("\n"))
	}
	var prefix []byte
	switch {
	case e.ItemID != "":
		prefix = u.flush(e.ItemID, e.SequenceNumber)
	case e.Type == "response.output_item.done" && e.Item != nil:
		prefix = u.flush(e.Item.ID, e.SequenceNumber)
	case strings.HasPrefix(e.Type, "response.completed") || strings.HasPrefix(e.Type, "response.failed") || strings.HasPrefix(e.Type, "response.incomplete"):
		prefix = u.flush("", e.SequenceNumber)
	}
	if bytes.Contains(data, []byte("SZ_")) {
		if rewritten, err := body.UnmaskResponse(data, u.table); err == nil {
			lines[at] = append([]byte("data: "), rewritten...)
		}
	}
	return append(prefix, bytes.Join(lines, []byte("\n"))...)
}
