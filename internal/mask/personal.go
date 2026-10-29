package mask

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	nameColumn     = regexp.MustCompile(`^(?:(?:first|last|given|family|middle|maiden|birth|full|contact|customer|holder|cardholder|account_holder|recipient|billing|shipping|patient|employee|guest)_?name|surname|forename|prenom|prénom|nom_complet|nom_de_famille|nom_famille|nom_naissance|nom_usage)$`)
	relatedName    = regexp.MustCompile(`^(?:name|nom|display_?name)$`)
	addressColumn  = regexp.MustCompile(`^(?:(?:street|billing|shipping|postal|home|delivery|invoice|mailing|residential)_?address(?:_?line)?_?[12]?|address(?:_?line)?_?[12]?|street(?:_?(?:address|line))?_?[12]?|adresse(?:_?(?:postale|ligne))?_?[12]?|rue)$`)
	contactColumn  = regexp.MustCompile(`^(?:e_?mail(?:_?address)?|mail|courriel|phone(?:_?number)?|mobile|telephone|téléphone|tel|portable)$`)
	firstColumn    = regexp.MustCompile(`^(?:first_?name|given_?name|prenom|prénom|forename)$`)
	camelBoundary  = regexp.MustCompile(`([\p{Ll}0-9])(\p{Lu})`)
	readPrefix     = regexp.MustCompile(`^ *\d+(?:\t|→)`)
	separatorLine  = regexp.MustCompile(`^[ \t]*[|+]?[ \t]*:?-{3,}[-+|:= \t]*$`)
	identifierCell = regexp.MustCompile(`^["'` + "`" + `]?[\p{L}_][\p{L}\p{N}_\-]*(?: [\p{L}\p{N}_\-]+){0,3}["'` + "`" + `]?$`)
	copyHeader     = regexp.MustCompile(`^COPY\s+[\w."]+\s*\(([^)]*)\)\s+FROM\s+stdin;\s*$`)
	insertHeader   = regexp.MustCompile("(?is)^INSERT\\s+INTO\\s+[\\w.\"`]+\\s*\\(([^)]*)\\)\\s*VALUES\\s*")
	fieldKey       = regexp.MustCompile("(?i)(?:^|[^\\p{L}0-9_\\-])([\"'`]?)((?:\\p{L}[\\p{L}0-9_\\-]*?)?(?:name|nom|address|adresse|street|rue)(?:[_\\-]?(?:line|ligne)?[_\\-]?[12])?)([\"'`]?)[ \\t]*(:|=|\\|)[ \\t]*")
	kvLine         = regexp.MustCompile("^[ \\t]*(?:- )?[\"'`]?[\\p{L}_][\\p{L}0-9_\\-]*[\"'`]?[ \\t]*[:=|]")
	relatedKey     = regexp.MustCompile("(?i)(?:^|[^\\p{L}0-9_\\-])[\"'`]?(?:e[_\\-]?mail(?:[_\\-]?address)?|mail|courriel|phone(?:[_\\-]?number)?|mobile|t[eé]l[eé]phone|tel|portable|pr[eé]nom|first[_\\-]?name|given[_\\-]?name)[\"'`]?[ \\t]*[:=|]")
)

var notPersonal = map[string]bool{
	"null": true, "none": true, "nil": true, `\n`: true, "-": true, "(null)": true, "[null]": true, "n/a": true, "undefined": true,
	"string": true, "str": true, "text": true, "varchar": true, "char": true, "optional": true, "any": true, "true": true, "false": true,
	"required": true, "unknown": true, "name": true, "nom": true, "id": true, "ville": true, "city": true, "pays": true, "country": true,
	"code_postal": true, "postal_code": true, "zip": true, "zipcode": true, "cp": true, "type": true, "role": true, "status": true,
	"statut": true, "date": true, "age": true, "sexe": true, "genre": true, "gender": true, "titre": true, "title": true, "civilite": true,
	"civility": true, "societe": true, "company": true, "entreprise": true, "email": true, "phone": true, "address": true, "adresse": true,
}

var organizations = regexp.MustCompile(`(?i)(?:^|[^\p{L}])(?:sas|sasu|sarl|eurl|sci|sa|llc|ltd|inc|gmbh)(?:$|[^\p{L}])`)

var hints = []string{"name", "nom", "dress", "street", "rue"}

var particles = map[string]bool{"de": true, "du": true, "des": true, "la": true, "le": true, "van": true, "von": true, "der": true, "di": true, "da": true, "del": true, "el": true, "al": true, "ben": true, "bin": true}

func columnKey(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "\"'`[]")
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	s = camelBoundary.ReplaceAllString(s, "${1}_${2}")
	return strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(s))
}

func columnKind(column string, related bool) Kind {
	k := columnKey(column)
	switch {
	case nameColumn.MatchString(k):
		return Name
	case addressColumn.MatchString(k):
		return Address
	case related && relatedName.MatchString(k):
		return Name
	}
	return ""
}

func relatedColumns(columns []string) bool {
	for _, c := range columns {
		if k := columnKey(c); contactColumn.MatchString(k) || firstColumn.MatchString(k) {
			return true
		}
	}
	return false
}

func columnWord(v string) bool {
	k := columnKey(v)
	return notPersonal[k] || columnKind(k, true) != "" || contactColumn.MatchString(k)
}

func personalValue(kind Kind, v string, strict bool) bool {
	if v == "" || len(v) > 150 || notPersonal[strings.ToLower(v)] || columnWord(v) {
		return false
	}
	for _, bad := range []string{"SZ_", "://", "@", "${", "{{", "%s", "<", ">", "`", "=", ":", ";", "|", "\\", "\"", "{", "}", "[", "]", "(", ")", "*", "#", "$"} {
		if strings.Contains(v, bad) {
			return false
		}
	}
	words := strings.Fields(v)
	letters, digits := 0, 0
	for _, r := range v {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		}
	}
	if letters == 0 {
		return false
	}
	if kind == Address {
		return len(words) >= 2 && len(words) <= 15 && digits > 0
	}
	if digits > 0 || len(words) > 5 || strings.ContainsAny(v, ",/") || organizations.MatchString(v) {
		return false
	}
	for i := 0; i+1 < len(v); i++ {
		if v[i] == '.' && v[i+1] != ' ' {
			return false
		}
	}
	if strict {
		for _, w := range words {
			if r, _ := utf8.DecodeRuneInString(w); !unicode.IsUpper(r) && !particles[strings.ToLower(strings.TrimRight(w, "'’"))] {
				return false
			}
		}
	}
	return true
}

type span struct{ start, end int }

func lines(text string) []span {
	var out []span
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\n')
		if end < 0 {
			if start < len(text) {
				out = append(out, span{start, len(text)})
			}
			break
		}
		out = append(out, span{start, start + end})
		start += end + 1
	}
	return out
}

func trimmed(text string, s span) span {
	for s.start < s.end && (text[s.start] == ' ' || text[s.start] == '\t') {
		s.start++
	}
	for s.end > s.start && (text[s.end-1] == ' ' || text[s.end-1] == '\t' || text[s.end-1] == '\r') {
		s.end--
	}
	return s
}

func withoutPrefix(text string, l span, strip bool) span {
	if strip {
		if loc := readPrefix.FindStringIndex(text[l.start:l.end]); loc != nil {
			l.start += loc[1]
		}
	}
	return l
}

func hasReadPrefix(text string, l span) bool {
	return readPrefix.MatchString(text[l.start:l.end])
}

func pipeCells(text string, l span) []span {
	l = trimmed(text, l)
	if l.start < l.end && text[l.start] == '|' {
		l.start++
	}
	if l.end > l.start && text[l.end-1] == '|' {
		l.end--
	}
	var cells []span
	for start := l.start; ; {
		i := strings.IndexByte(text[start:l.end], '|')
		if i < 0 {
			return append(cells, trimmed(text, span{start, l.end}))
		}
		cells = append(cells, trimmed(text, span{start, start + i}))
		start += i + 1
	}
}

func delimitedCells(text string, l span, delim byte) []span {
	var cells []span
	for pos := l.start; ; {
		var cell span
		if pos < l.end && text[pos] == '"' {
			i := pos + 1
			for i < l.end && !(text[i] == '"' && (i+1 >= l.end || text[i+1] != '"')) {
				if text[i] == '"' {
					i++
				}
				i++
			}
			cell = span{pos + 1, min(i, l.end)}
			pos = min(i+1, l.end)
			for pos < l.end && text[pos] != delim {
				pos++
			}
		} else {
			i := strings.IndexByte(text[pos:l.end], delim)
			if i < 0 {
				i = l.end - pos
			}
			cell = trimmed(text, span{pos, pos + i})
			pos += i
		}
		cells = append(cells, cell)
		if pos >= l.end {
			return cells
		}
		pos++
	}
}

func texts(text string, cells []span) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = text[c.start:c.end]
	}
	return out
}

func kinds(columns []string) ([]Kind, bool) {
	related := relatedColumns(columns)
	out := make([]Kind, len(columns))
	any := false
	for i, c := range columns {
		out[i] = columnKind(c, related)
		any = any || out[i] != ""
	}
	return out, any
}

func cellFindings(text string, cells []span, ks []Kind) []Finding {
	var out []Finding
	for i, c := range cells {
		if i < len(ks) && ks[i] != "" && personalValue(ks[i], text[c.start:c.end], false) {
			out = append(out, Finding{Start: c.start, End: c.end, Kind: ks[i], Value: text[c.start:c.end]})
		}
	}
	return out
}

func pipeTable(text string, ls []span, i int) (int, []Finding) {
	if i+1 >= len(ls) || !strings.ContainsRune(text[ls[i].start:ls[i].end], '|') {
		return 0, nil
	}
	strip := hasReadPrefix(text, ls[i])
	head := withoutPrefix(text, ls[i], strip)
	if !separatorLine.MatchString(text[withoutPrefix(text, ls[i+1], strip).start:ls[i+1].end]) {
		return 0, nil
	}
	header := pipeCells(text, head)
	ks, any := kinds(texts(text, header))
	if len(header) < 2 || !any {
		return 0, nil
	}
	var out []Finding
	n := 2
	for ; i+n < len(ls); n++ {
		row := withoutPrefix(text, ls[i+n], strip)
		if separatorLine.MatchString(text[row.start:row.end]) {
			continue
		}
		cells := pipeCells(text, row)
		if !strings.ContainsRune(text[row.start:row.end], '|') || len(cells) != len(header) {
			break
		}
		out = append(out, cellFindings(text, cells, ks)...)
	}
	return n, out
}

func delimitedTable(text string, ls []span, i int) (int, []Finding) {
	strip := hasReadPrefix(text, ls[i])
	head := withoutPrefix(text, ls[i], strip)
	line := text[head.start:head.end]
	var delim byte
	best := 0
	for _, d := range []byte{'\t', ';', ','} {
		if n := strings.Count(line, string(d)); n > best {
			delim, best = d, n
		}
	}
	if best == 0 {
		return 0, nil
	}
	header := delimitedCells(text, head, delim)
	for _, c := range header {
		if !identifierCell.MatchString(text[c.start:c.end]) {
			return 0, nil
		}
	}
	ks, any := kinds(texts(text, header))
	if !any {
		return 0, nil
	}
	var out []Finding
	n := 1
	for ; i+n < len(ls); n++ {
		row := withoutPrefix(text, ls[i+n], strip)
		cells := delimitedCells(text, row, delim)
		if row.start == row.end || len(cells) != len(header) {
			break
		}
		out = append(out, cellFindings(text, cells, ks)...)
	}
	return n, out
}

func copyTable(text string, ls []span, i int) (int, []Finding) {
	m := copyHeader.FindStringSubmatch(text[ls[i].start:ls[i].end])
	if m == nil {
		return 0, nil
	}
	ks, any := kinds(strings.Split(m[1], ","))
	if !any {
		return 0, nil
	}
	var out []Finding
	n := 1
	for ; i+n < len(ls) && text[ls[i+n].start:ls[i+n].end] != `\.`; n++ {
		cells := delimitedCells(text, ls[i+n], '\t')
		if len(cells) != len(ks) {
			break
		}
		out = append(out, cellFindings(text, cells, ks)...)
	}
	return n, out
}

func insertTable(text string, ls []span, i int) (int, []Finding) {
	m := insertHeader.FindStringSubmatchIndex(text[ls[i].start:])
	if m == nil {
		return 0, nil
	}
	ks, any := kinds(strings.Split(text[ls[i].start+m[2]:ls[i].start+m[3]], ","))
	if !any {
		return 0, nil
	}
	var out []Finding
	pos := ls[i].start + m[1]
	skip := func() {
		for pos < len(text) && strings.IndexByte(" \t\r\n", text[pos]) >= 0 {
			pos++
		}
	}
	for {
		skip()
		if pos >= len(text) || text[pos] != '(' {
			break
		}
		pos++
		var cells []span
		for pos < len(text) && text[pos] != ')' {
			skip()
			if pos < len(text) && text[pos] == '\'' {
				start := pos + 1
				pos++
				for pos < len(text) && (text[pos] != '\'' || (pos+1 < len(text) && text[pos+1] == '\'')) {
					if text[pos] == '\'' || text[pos] == '\\' {
						pos++
					}
					pos++
				}
				cells = append(cells, span{start, min(pos, len(text))})
				pos++
			} else {
				start := pos
				for pos < len(text) && text[pos] != ',' && text[pos] != ')' {
					pos++
				}
				cells = append(cells, trimmed(text, span{start, pos}))
			}
			skip()
			if pos < len(text) && text[pos] == ',' {
				pos++
			}
		}
		if len(cells) == len(ks) {
			out = append(out, cellFindings(text, cells, ks)...)
		}
		pos++
		skip()
		if pos >= len(text) || text[pos] != ',' {
			break
		}
		pos++
	}
	n := 1
	for i+n < len(ls) && ls[i+n].start < pos {
		n++
	}
	return n, out
}

func hintSpans(text string) []span {
	var out []span
	for i := 0; i < len(text); i++ {
		if c := text[i] | 0x20; c != 'n' && c != 'd' && c != 's' && c != 'r' {
			continue
		}
		for _, h := range hints {
			if len(text)-i < len(h) || !foldEqual(text[i:i+len(h)], h) {
				continue
			}
			if h == "rue" && ((i > 0 && identByte(text[i-1])) || (i+3 < len(text) && identByte(text[i+3]))) {
				break
			}
			out = append(out, span{i, i + len(h)})
			i += len(h) - 1
			break
		}
	}
	return out
}

func foldEqual(s, lower string) bool {
	for i := 0; i < len(lower); i++ {
		if s[i]|0x20 != lower[i] {
			return false
		}
	}
	return true
}

func tableFindings(text string, hs []span) []Finding {
	ls := lines(text)
	var out []Finding
	j := 0
	for i := 0; i < len(ls); i++ {
		for j < len(hs) && hs[j].start < ls[i].start {
			j++
		}
		line := text[ls[i].start:ls[i].end]
		if j >= len(hs) || hs[j].start >= ls[i].end || !strings.ContainsAny(line, "|,;\t(") {
			continue
		}
		for _, parse := range []func(string, []span, int) (int, []Finding){copyTable, insertTable, pipeTable, delimitedTable} {
			if n, found := parse(text, ls, i); n > 0 {
				out = append(out, found...)
				i += n - 1
				break
			}
		}
	}
	return out
}

func enclosingObject(text string, pos int) (span, bool) {
	depth := 0
	for i := pos - 1; i >= 0 && pos-i < 4096; i-- {
		switch text[i] {
		case '}':
			depth++
		case '{':
			if depth == 0 {
				for j := i + 1; j < len(text) && j-i < 8192; j++ {
					switch text[j] {
					case '{':
						depth++
					case '}':
						if depth == 0 {
							return span{i, j + 1}, true
						}
						depth--
					}
				}
				return span{i, min(len(text), i+8192)}, true
			}
			depth--
		}
	}
	return span{}, false
}

func indentation(line string) int {
	n := len(line) - len(strings.TrimLeft(line, " \t"))
	if strings.HasPrefix(line[n:], "- ") {
		n += 2
	}
	return n
}

func lineAt(text string, pos int) span {
	start := strings.LastIndexByte(text[:pos], '\n') + 1
	end := strings.IndexByte(text[pos:], '\n')
	if end < 0 {
		return span{start, len(text)}
	}
	return span{start, pos + end}
}

func enclosingRecord(text string, pos int) span {
	cur := lineAt(text, pos)
	indent := indentation(text[cur.start:cur.end])
	same := func(l span) bool {
		line := text[l.start:l.end]
		return kvLine.MatchString(line) && indentation(line) == indent
	}
	first, last := cur, cur
	for n := 0; n < 50 && first.start > 0; n++ {
		prev := lineAt(text, first.start-1)
		if !same(prev) {
			break
		}
		first = prev
	}
	for n := 0; n < 50 && last.end < len(text); n++ {
		next := lineAt(text, last.end+1)
		if !same(next) {
			break
		}
		last = next
	}
	return span{first.start, last.end}
}

func relatedNear(text string, pos int) bool {
	s, ok := enclosingObject(text, pos)
	if !ok {
		s = enclosingRecord(text, pos)
	}
	return relatedKey.MatchString(text[s.start:s.end])
}

func fieldValue(text string, pos int, sep string) span {
	end := strings.IndexByte(text[pos:], '\n')
	if end < 0 {
		end = len(text)
	} else {
		end += pos
	}
	if pos >= end {
		return span{}
	}
	switch q := text[pos]; q {
	case '"', '\'':
		i := pos + 1
		for i < end {
			if text[i] == '\\' {
				i += 2
				continue
			}
			if text[i] == q {
				if q == '\'' && i+1 < end && text[i+1] == '\'' {
					i += 2
					continue
				}
				break
			}
			i++
		}
		if i >= end {
			return span{}
		}
		return span{pos + 1, i}
	}
	if sep == "|" {
		if i := strings.IndexByte(text[pos:end], '|'); i >= 0 {
			end = pos + i
		}
	}
	v := trimmed(text, span{pos, end})
	for v.end > v.start && (text[v.end-1] == ',' || text[v.end-1] == ';') {
		v.end--
	}
	return v
}

func nextIsSeparator(text string, pos int) bool {
	nl := strings.IndexByte(text[pos:], '\n')
	if nl < 0 {
		return false
	}
	rest := text[pos+nl+1:]
	if e := strings.IndexByte(rest, '\n'); e >= 0 {
		rest = rest[:e]
	}
	return separatorLine.MatchString(rest)
}

func lineStart(text string, pos int) bool {
	line := text[strings.LastIndexByte(text[:pos], '\n')+1 : pos]
	return strings.Trim(line, " \t|") == ""
}

func identByte(c byte) bool {
	return c >= 0x80 || c == '_' || c == '-' || (c >= '0' && c <= '9') || (c|0x20 >= 'a' && c|0x20 <= 'z')
}

func fieldMatches(text string, hs []span) [][]int {
	var out [][]int
	last := -1
	for _, h := range hs {
		start := h.start
		for start > 0 && h.start-start < 80 && identByte(text[start-1]) {
			start--
		}
		start = max(0, start-1)
		end := min(len(text), h.end+120)
		for _, m := range fieldKey.FindAllStringSubmatchIndex(text[start:end], -1) {
			if start+m[4] > h.start || start+m[5] < h.end || start+m[4] == last {
				continue
			}
			for i := range m {
				if m[i] >= 0 {
					m[i] += start
				}
			}
			last = m[4]
			out = append(out, m)
		}
	}
	return out
}

func fieldFindings(text string, hs []span) []Finding {
	var out []Finding
	for _, m := range fieldMatches(text, hs) {
		open, key, close, sep := text[m[2]:m[3]], text[m[4]:m[5]], text[m[6]:m[7]], text[m[8]:m[9]]
		kind := columnKind(key, false)
		if open != close || (kind == "" && columnKind(key, true) == "") {
			continue
		}
		if sep == "|" && (nextIsSeparator(text, m[1]) || !lineStart(text, m[2])) {
			continue
		}
		v := fieldValue(text, m[1], sep)
		if v.start == v.end {
			continue
		}
		if kind == "" {
			if !relatedNear(text, m[4]) {
				continue
			}
			kind = Name
		}
		if personalValue(kind, text[v.start:v.end], true) {
			out = append(out, Finding{Start: v.start, End: v.end, Kind: kind, Value: text[v.start:v.end]})
		}
	}
	return out
}

func personalFindings(text string) []Finding {
	hs := hintSpans(text)
	if len(hs) == 0 {
		return nil
	}
	return append(tableFindings(text, hs), fieldFindings(text, hs)...)
}
