package mask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const remaskMinLength = 8

var Placeholder = regexp.MustCompile(`SZ_[A-Z]+_[0-9a-f]{12}`)

type Finding struct {
	Start, End int
	Kind       Kind
	Value      string
	Name       string
}

type Entry struct {
	Token string
	Kind  Kind
	Name  string
}

type Masker struct {
	key   []byte
	cache *findCache
}

func New(key []byte) *Masker {
	return &Masker{key: key, cache: newFindCache(20000)}
}

func (m *Masker) token(kind Kind, value string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(value))
	return "SZ_" + string(kind) + "_" + hex.EncodeToString(mac.Sum(nil))[:12]
}

func (m *Masker) find(text string) []Finding {
	if found, ok := m.cache.get(text); ok {
		return found
	}
	var spans []Finding
	for _, r := range rules {
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := loc[2*r.value], loc[2*r.value+1]
			if start < 0 {
				continue
			}
			value := text[start:end]
			if r.bounded && !isolated(text, start, end) {
				continue
			}
			if r.valid != nil && !r.valid(value) {
				continue
			}
			f := Finding{Start: start, End: end, Kind: r.kind, Value: value}
			if r.name > 0 {
				f.Name = text[loc[2*r.name]:loc[2*r.name+1]]
			}
			spans = append(spans, f)
		}
	}
	sort.SliceStable(spans, func(a, b int) bool {
		if spans[a].Start != spans[b].Start {
			return spans[a].Start < spans[b].Start
		}
		if la, lb := spans[a].End-spans[a].Start, spans[b].End-spans[b].Start; la != lb {
			return la > lb
		}
		return spans[a].Name != "" && spans[b].Name == ""
	})
	kept := spans[:0]
	end := -1
	for _, s := range spans {
		if s.Start >= end {
			kept = append(kept, s)
			end = s.End
		}
	}
	m.cache.put(text, kept)
	return kept
}

type Record struct {
	Kind  Kind   `json:"k"`
	Name  string `json:"n,omitempty"`
	Value string `json:"v"`
}

type Table struct {
	m        *Masker
	forward  map[string]string
	backward map[string]string
	entries  map[string]Entry
	values   map[string]string
	used     map[string]bool
	order    []string
	added    int
	replacer *strings.Replacer
}

func (m *Masker) NewTable() *Table {
	return &Table{m: m, forward: map[string]string{}, backward: map[string]string{}, entries: map[string]Entry{}, values: map[string]string{}, used: map[string]bool{}}
}

func (t *Table) store(kind Kind, value, name string) string {
	tok := t.m.token(kind, value)
	t.forward[value] = tok
	t.backward[tok] = value
	t.entries[tok] = Entry{Token: tok, Kind: kind, Name: name}
	t.values[tok] = value
	t.replacer = nil
	return tok
}

func (t *Table) add(kind Kind, value, name string) string {
	tok, ok := t.forward[value]
	if !ok {
		tok = t.store(kind, value, name)
		t.added++
	}
	if !t.used[tok] {
		t.used[tok] = true
		t.order = append(t.order, tok)
	}
	return tok
}

func (t *Table) Import(records []Record) {
	for _, r := range records {
		if _, ok := t.forward[r.Value]; !ok {
			t.store(r.Kind, r.Value, r.Name)
		}
	}
}

func (t *Table) Records() []Record {
	out := make([]Record, 0, len(t.values))
	for tok, v := range t.values {
		e := t.entries[tok]
		out = append(out, Record{Kind: e.Kind, Name: e.Name, Value: v})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Value < out[b].Value })
	return out
}

func (t *Table) Added() int { return t.added }

func (t *Table) Learn(text string) {
	for _, f := range t.m.find(text) {
		t.add(f.Kind, f.Value, f.Name)
	}
}

func jsonEscaped(v string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	s := strings.TrimSuffix(b.String(), "\n")
	return s[1 : len(s)-1]
}

func (t *Table) known() *strings.Replacer {
	if t.replacer != nil {
		return t.replacer
	}
	type pair struct{ old, token string }
	var pairs []pair
	for v, tok := range t.forward {
		if len(v) < remaskMinLength {
			continue
		}
		pairs = append(pairs, pair{v, tok})
		if esc := jsonEscaped(v); esc != v {
			pairs = append(pairs, pair{esc, tok})
		}
	}
	sort.Slice(pairs, func(a, b int) bool {
		if len(pairs[a].old) != len(pairs[b].old) {
			return len(pairs[a].old) > len(pairs[b].old)
		}
		return pairs[a].old < pairs[b].old
	})
	args := make([]string, 0, 2*len(pairs))
	for _, p := range pairs {
		args = append(args, p.old, p.token)
	}
	t.replacer = strings.NewReplacer(args...)
	return t.replacer
}

func (t *Table) Mask(text string) string {
	found := t.m.find(text)
	known := t.known()
	var out strings.Builder
	pos := 0
	for _, f := range found {
		out.WriteString(known.Replace(text[pos:f.Start]))
		out.WriteString(t.add(f.Kind, f.Value, f.Name))
		pos = f.End
	}
	out.WriteString(known.Replace(text[pos:]))
	masked := out.String()
	if strings.Contains(masked, "SZ_") {
		for _, tok := range Placeholder.FindAllString(masked, -1) {
			if _, ok := t.entries[tok]; ok && !t.used[tok] {
				t.used[tok] = true
				t.order = append(t.order, tok)
			}
		}
	}
	return masked
}

func (t *Table) unmask(text string, encode func(string) string) string {
	if !strings.Contains(text, "SZ_") {
		return text
	}
	return Placeholder.ReplaceAllStringFunc(text, func(tok string) string {
		if v, ok := t.backward[tok]; ok {
			return encode(v)
		}
		return tok
	})
}

func (t *Table) Unmask(text string) string {
	return t.unmask(text, func(v string) string { return v })
}

func (t *Table) UnmaskJSON(text string) string {
	return t.unmask(text, jsonEscaped)
}

func (t *Table) Entries() []Entry {
	out := make([]Entry, 0, len(t.order))
	for _, tok := range t.order {
		out = append(out, t.entries[tok])
	}
	return out
}

type findCache struct {
	mu       sync.Mutex
	limit    int
	current  map[[32]byte][]Finding
	previous map[[32]byte][]Finding
}

func newFindCache(limit int) *findCache {
	return &findCache{limit: limit, current: map[[32]byte][]Finding{}, previous: map[[32]byte][]Finding{}}
}

const cacheMinLength = 256

func (c *findCache) get(text string) ([]Finding, bool) {
	if len(text) < cacheMinLength {
		return nil, false
	}
	key := sha256.Sum256([]byte(text))
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.current[key]; ok {
		return f, true
	}
	if f, ok := c.previous[key]; ok {
		c.current[key] = f
		return f, true
	}
	return nil, false
}

func (c *findCache) put(text string, found []Finding) {
	if len(text) < cacheMinLength {
		return
	}
	key := sha256.Sum256([]byte(text))
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.current) >= c.limit {
		c.previous, c.current = c.current, map[[32]byte][]Finding{}
	}
	c.current[key] = found
}
