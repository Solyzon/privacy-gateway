package body

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Solyzon/privacy-gateway/internal/mask"
)

var protectedKeys = map[string]bool{
	"signature": true, "id": true, "tool_use_id": true, "model": true, "type": true, "role": true, "media_type": true,
	"call_id": true, "item_id": true, "response_id": true, "previous_response_id": true, "encrypted_content": true,
	"prompt_cache_key": true, "obfuscation": true,
}

var opaqueTypes = map[string]bool{"thinking": true, "redacted_thinking": true, "base64": true, "reasoning": true}

var jsonTextKeys = map[string]bool{"partial_json": true, "arguments": true, "input": true}

func JSONText(key, s string) bool {
	return jsonTextKeys[key] && !strings.HasPrefix(s, "*** Begin Patch")
}

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

func (n *node) strings(key string, visit func(n *node, key string)) {
	switch n.kind {
	case 's':
		if !strings.HasPrefix(n.text, "data:") {
			visit(n, key)
		}
	case 'a':
		for _, v := range n.values {
			v.strings(key, visit)
		}
	case 'o':
		if t := n.field("type"); t != nil && t.kind == 's' && opaqueTypes[t.text] {
			return
		}
		for i, v := range n.values {
			if !protectedKeys[n.keys[i]] {
				v.strings(n.keys[i], visit)
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

func rewrite(b []byte, root *node, fn func(key, text string) string) []byte {
	var out bytes.Buffer
	pos := 0
	root.strings("", func(n *node, key string) {
		next := fn(key, n.text)
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
	table := m.NewTable()
	out, err := MaskWith(b, table)
	return out, table, err
}

func MaskWith(b []byte, table *mask.Table) ([]byte, error) {
	root, err := parse(b)
	if err != nil {
		return nil, err
	}
	root.strings("", func(n *node, _ string) { table.Learn(n.text) })
	return rewrite(b, root, func(_, s string) string { return table.Mask(s) }), nil
}

func Rewrite(b []byte, fn func(key, text string) string) ([]byte, error) {
	root, err := parse(b)
	if err != nil {
		return nil, err
	}
	return rewrite(b, root, fn), nil
}

func UnmaskResponse(b []byte, table *mask.Table) ([]byte, error) {
	return Rewrite(b, func(key, s string) string {
		if JSONText(key, s) {
			return table.UnmaskJSON(s)
		}
		return table.Unmask(s)
	})
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

const PlaceholderNote = "Values shaped like SZ_<KIND>_<12 hex digits> are placeholders set by a local privacy gateway for secrets or personal data you cannot see. Use them exactly as written in code, commands and answers: the real value replaces them before any tool runs and before the user reads your answer. Never guess, compare or check the real value, its length or its format, and never say the value is fake or unknown."

func AddSystemNote(b []byte, note string) ([]byte, error) {
	root, err := parse(b)
	if err != nil || root.kind != 'o' {
		return nil, errSyntax
	}
	block := `{"type":"text","text":` + string(encode(note)) + `}`
	insert := func(at int, text string) []byte {
		out := make([]byte, 0, len(b)+len(text))
		out = append(out, b[:at]...)
		out = append(out, text...)
		return append(out, b[at:]...)
	}
	system := root.field("system")
	switch {
	case system == nil:
		sep := ","
		if len(root.values) == 0 {
			sep = ""
		}
		return insert(root.end-1, sep+`"system":[`+block+`]`), nil
	case system.kind == 's':
		var out []byte
		out = append(out, b[:system.start]...)
		out = append(out, encode(system.text+"\n\n"+note)...)
		return append(out, b[system.end:]...), nil
	case system.kind == 'a':
		sep := ","
		if len(system.values) == 0 {
			sep = ""
		}
		return insert(system.end-1, sep+block), nil
	}
	return b, nil
}

type Attachment struct {
	Kind string
	Hash string
}

func attachmentKind(mediaType string) string {
	switch {
	case mediaType == "application/pdf":
		return "PDF"
	case strings.HasPrefix(mediaType, "image/"):
		return "image"
	}
	return "fichier"
}

func Attachments(b []byte) []Attachment {
	if !bytes.Contains(b, []byte(`"base64"`)) && !bytes.Contains(b, []byte(`"data:`)) {
		return nil
	}
	root, err := parse(b)
	if err != nil {
		return nil
	}
	var out []Attachment
	var walk func(n *node)
	walk = func(n *node) {
		switch n.kind {
		case 'a':
			for _, v := range n.values {
				walk(v)
			}
		case 'o':
			kind, data := "", ""
			if t := n.field("type"); t != nil && t.text == "base64" {
				if m := n.field("media_type"); m != nil {
					kind = attachmentKind(m.text)
				}
				if d := n.field("data"); d != nil {
					data = d.text
				}
			}
			for _, v := range n.values {
				if v.kind == 's' && strings.HasPrefix(v.text, "data:") {
					media := strings.TrimPrefix(v.text[:strings.IndexAny(v.text+";,", ";,")], "data:")
					out = append(out, Attachment{Kind: attachmentKind(media), Hash: digest(v.text)})
				}
			}
			if kind != "" {
				out = append(out, Attachment{Kind: kind, Hash: digest(data)})
				return
			}
			for _, v := range n.values {
				walk(v)
			}
		}
	}
	walk(root)
	return out
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
