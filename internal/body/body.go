package body

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Solyzon/privacy-gateway/internal/mask"
)

var protectedKeys = map[string]bool{"signature": true, "id": true, "tool_use_id": true, "model": true, "type": true, "role": true, "media_type": true}

var opaqueTypes = map[string]bool{"thinking": true, "redacted_thinking": true, "base64": true}

type node struct {
	start, end int
	kind       byte
	keys       []string
	values     []*node
	text       string
}

type parser struct {
	b   []byte
	pos int
}

var errSyntax = errors.New("invalid JSON body")

func parse(b []byte) (*node, error) {
	if !json.Valid(b) {
		return nil, errSyntax
	}
	p := &parser{b: b}
	return p.value()
}

func (p *parser) space() {
	for p.pos < len(p.b) && (p.b[p.pos] == ' ' || p.b[p.pos] == '\n' || p.b[p.pos] == '\r' || p.b[p.pos] == '\t') {
		p.pos++
	}
}

func (p *parser) value() (*node, error) {
	p.space()
	n := &node{start: p.pos}
	switch p.b[p.pos] {
	case '{':
		n.kind = 'o'
		p.pos++
		for {
			p.space()
			if p.b[p.pos] == '}' {
				p.pos++
				break
			}
			key, err := p.value()
			if err != nil {
				return nil, err
			}
			p.space()
			p.pos++
			val, err := p.value()
			if err != nil {
				return nil, err
			}
			n.keys = append(n.keys, key.text)
			n.values = append(n.values, val)
			p.space()
			if p.b[p.pos] == ',' {
				p.pos++
			}
		}
	case '[':
		n.kind = 'a'
		p.pos++
		for {
			p.space()
			if p.b[p.pos] == ']' {
				p.pos++
				break
			}
			val, err := p.value()
			if err != nil {
				return nil, err
			}
			n.values = append(n.values, val)
			p.space()
			if p.b[p.pos] == ',' {
				p.pos++
			}
		}
	case '"':
		n.kind = 's'
		p.pos++
		escaped := false
		for p.b[p.pos] != '"' {
			if p.b[p.pos] == '\\' {
				escaped = true
				p.pos++
			}
			p.pos++
		}
		p.pos++
		raw := p.b[n.start:p.pos]
		if escaped {
			if err := json.Unmarshal(raw, &n.text); err != nil {
				return nil, err
			}
		} else {
			n.text = string(raw[1 : len(raw)-1])
		}
	default:
		n.kind = 'x'
		for p.pos < len(p.b) && !bytes.ContainsRune([]byte(",}] \n\r\t"), rune(p.b[p.pos])) {
			p.pos++
		}
	}
	n.end = p.pos
	return n, nil
}

func (n *node) field(key string) *node {
	for i, k := range n.keys {
		if k == key {
			return n.values[i]
		}
	}
	return nil
}

func (n *node) strings(visit func(*node)) {
	switch n.kind {
	case 's':
		visit(n)
	case 'a':
		for _, v := range n.values {
			v.strings(visit)
		}
	case 'o':
		if t := n.field("type"); t != nil && t.kind == 's' && opaqueTypes[t.text] {
			return
		}
		for i, v := range n.values {
			if !protectedKeys[n.keys[i]] {
				v.strings(visit)
			}
		}
	}
}

func encode(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func rewrite(b []byte, root *node, fn func(string) string) []byte {
	var out bytes.Buffer
	pos := 0
	root.strings(func(n *node) {
		next := fn(n.text)
		if next == n.text {
			return
		}
		out.Write(b[pos:n.start])
		out.Write(encode(next))
		pos = n.end
	})
	if pos == 0 {
		return b
	}
	out.Write(b[pos:])
	return out.Bytes()
}

func MaskRequest(b []byte, m *mask.Masker) ([]byte, *mask.Table, error) {
	root, err := parse(b)
	if err != nil {
		return nil, nil, err
	}
	table := m.NewTable()
	root.strings(func(n *node) { table.Learn(n.text) })
	return rewrite(b, root, table.Mask), table, nil
}

func UnmaskResponse(b []byte, table *mask.Table) ([]byte, error) {
	root, err := parse(b)
	if err != nil {
		return nil, err
	}
	return rewrite(b, root, table.Unmask), nil
}

func SessionID(b []byte) string {
	root, err := parse(b)
	if err != nil || root.kind != 'o' {
		return ""
	}
	meta := root.field("metadata")
	if meta == nil || meta.kind != 'o' {
		return ""
	}
	user := meta.field("user_id")
	if user == nil || user.kind != 's' {
		return ""
	}
	if i := strings.LastIndex(user.text, "_session_"); i >= 0 {
		return user.text[i+len("_session_"):]
	}
	var nested struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal([]byte(user.text), &nested) == nil {
		return nested.SessionID
	}
	return ""
}
