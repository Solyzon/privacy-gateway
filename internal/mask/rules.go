package mask

import (
	"math/big"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Kind string

const (
	Secret  Kind = "SECRET"
	IBAN    Kind = "IBAN"
	NIR     Kind = "NIR"
	Card    Kind = "CARD"
	Email   Kind = "EMAIL"
	Phone   Kind = "PHONE"
	Name    Kind = "NAME"
	Address Kind = "ADDRESS"
)

type rule struct {
	kind    Kind
	re      *regexp.Regexp
	value   int
	name    int
	bounded bool
	valid   func(string) bool
}

var rules = []rule{
	{kind: Secret, re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----`)},
	{kind: Secret, re: regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{kind: Secret, re: regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{20,}`)},
	{kind: Secret, re: regexp.MustCompile(`sk-[A-Za-z0-9]{32,}`)},
	{kind: Secret, re: regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`)},
	{kind: Secret, re: regexp.MustCompile(`whsec_[A-Za-z0-9]{24,}`)},
	{kind: Secret, re: regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	{kind: Secret, re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{kind: Secret, re: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{40,}`)},
	{kind: Secret, re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{kind: Secret, re: regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`)},
	{kind: Secret, re: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{kind: Secret, re: regexp.MustCompile(`[a-z][a-z0-9+.\-]*://[^:/\s@]+:([^@\s/]+)@`), value: 1},
	{kind: Secret, re: regexp.MustCompile(`(?m)^(?:[ \t]*\d+(?:\t|→)|[^\s:]*:(?:\d+:)?|[ \t]*-[ \t]+)?[ \t]*(?:export[ \t]+)?([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|(?:API|SECRET|PRIVATE|ACCESS|CONSUMER|APP|SIGNING|ENCRYPTION|MASTER|LICENSE|CLIENT|SERVICE|AUTH)_?KEY|CREDENTIALS?|AUTH|DSN)(?:_\d+)?)[ \t]*[=:][ \t]*["']?([^\s"'#(),]{6,})["']?[ \t]*$`), value: 2, name: 1},
	{kind: Secret, re: regexp.MustCompile(`(?i)"([a-z0-9_\-]*(?:password|passwd|secret|token|api[_\-]?key|private[_\-]?key|access[_\-]?key))"[ \t]*:[ \t]*"([^"\\\s]{6,})"`), value: 2, name: 1},
	{kind: Secret, re: regexp.MustCompile(`(?im)^[ \t]*(?:-[ \t]+)?([a-z0-9_\-]*(?:password|passwd|secret|token|api[_\-]?key|private[_\-]?key|access[_\-]?key)):[ \t]+["']?([^\s"'#(),\[\]{}$]{6,})["']?[ \t]*$`), value: 2, name: 1},
	{kind: IBAN, re: regexp.MustCompile(`[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?`), bounded: true, valid: validIBAN},
	{kind: NIR, re: regexp.MustCompile(`[12] ?\d{2} ?(?:0[1-9]|1[0-2]) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}`), bounded: true, valid: validNIR},
	{kind: Card, re: regexp.MustCompile(`(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)(?:[ \-]?\d{4}){3}`), bounded: true, valid: luhn},
	{kind: Email, re: regexp.MustCompile(`[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}\-]+(?:\.[\p{L}\p{N}\-]+)*\.\p{L}{2,}`), valid: personalEmail},
	{kind: Phone, re: regexp.MustCompile(`(?:\+33 ?|0)[1-9](?:[ .\-]?\d{2}){4}`), bounded: true, valid: notDigitRun},
	{kind: Phone, re: regexp.MustCompile(`\+[1-9]\d{0,2}(?:[ .\-]?\d{2,4}){3,5}`), bounded: true, valid: phoneLength},
	{kind: Name, re: regexp.MustCompile(`\b(?:M\.|Mme\.?|Mlle\.?|Monsieur|Madame|Mademoiselle|Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Docteur|Maître)[ \t]+(\p{Lu}(?:\.|[\p{L}'’\-]+)(?:[ \t]+(?:(?:de|du|des|la|le|van|von|di|da|d'|l')[ \t]*)?\p{Lu}[\p{L}'’\-]+){0,3})`), value: 1, valid: notCommonWord},
	{kind: Address, re: regexp.MustCompile(`\b\d{1,4}(?:[ \t]?(?:bis|ter|quater|[A-D]))?,?[ \t]+(?i:rue|avenue|av\.|boulevard|bd|chemin|allée|allee|impasse|place|route|quai|cours|square|passage|sentier|voie|résidence|residence|lotissement|faubourg|rond-point|esplanade|parvis|promenade|hameau|cité|villa)[ \t]+(?:(?:de|du|des|la|le|les|d'|l'|d’|l’)[ \t]*)*\p{Lu}[\p{L}'’\-]*(?:[ \t]+(?:(?:de|du|des|la|le|les|et|sur|sous|en|d'|l'|d’|l’)[ \t]*)*\p{Lu}[\p{L}'’\-]*){0,5}(?:,?[ \t]+\d{5}[ \t]+\p{Lu}[\p{L}'’\-]*(?:[ \t\-]+\p{Lu}[\p{L}'’\-]*){0,3})?`)},
	{kind: Address, re: regexp.MustCompile(`\b\d{1,5}[ \t]+(?:\p{Lu}[\p{L}'\-]*[ \t]+){1,4}(?:Street|St\.|Avenue|Ave\.|Road|Rd\.|Lane|Drive|Boulevard|Blvd\.?)`)},
}

var technicalMailboxes = map[string]bool{"root": true, "git": true, "ubuntu": true, "debian": true, "postgres": true, "www-data": true}

var publicDomains = []string{"example.com", "example.org", "example.net", "noreply.github.com", "users.noreply.gitlab.com"}

func personalEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	if technicalMailboxes[strings.ToLower(v[:at])] {
		return false
	}
	domain := strings.ToLower(v[at+1:])
	for _, d := range publicDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return false
		}
	}
	return true
}

func notCommonWord(v string) bool { return !notPersonal[strings.ToLower(v)] }

func digitsOnly(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, v)
}

func notDigitRun(v string) bool { return digitsOnly(v) != "0123456789" }

func phoneLength(v string) bool {
	n := len(digitsOnly(v))
	return n >= 8 && n <= 15
}

func validIBAN(v string) bool {
	raw := strings.ReplaceAll(v, " ", "")
	if len(raw) < 15 || len(raw) > 34 {
		return false
	}
	var digits strings.Builder
	for _, r := range raw[4:] + raw[:4] {
		if r >= 'A' && r <= 'Z' {
			digits.WriteString(big.NewInt(int64(r-'A') + 10).String())
		} else {
			digits.WriteRune(r)
		}
	}
	n, ok := new(big.Int).SetString(digits.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

func validNIR(v string) bool {
	raw := strings.ReplaceAll(v, " ", "")
	body, key := raw[:13], raw[13:]
	body = strings.NewReplacer("2A", "19", "2B", "18").Replace(body)
	n, ok := new(big.Int).SetString(body, 10)
	k, ok2 := new(big.Int).SetString(key, 10)
	return ok && ok2 && 97-new(big.Int).Mod(n, big.NewInt(97)).Int64() == k.Int64()
}

func luhn(v string) bool {
	d := digitsOnly(v)
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if (len(d)-i)%2 == 0 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

func alnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

func isolated(text string, start, end int) bool {
	if start > 0 {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); alnum(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); alnum(r) {
			return false
		}
	}
	return true
}
