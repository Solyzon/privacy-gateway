package mask

import (
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var secrets = map[string]string{
	"ANTHROPIC_API_KEY":     "sk-ant-api03-Zq8vT3kLmN2pR7sX9wY4bC6dF1gH5jK0aE3iO8uQ2tV7",
	"GITLAB_TOKEN":          "glpat-EXAMPLE",
	"AWS_ACCESS_KEY_ID":     "AKIAZ7QX3M9P2LK4RT8W",
	"DB_PASSWORD":           "Tr0ub4dor&3-horse",
	"SESSION_SECRET":        "f3a9c1e7b2d84a6f9e0c5b7a1d3e8f2c",
	"DATABASE_URL_PASSWORD": "pgS3cretValue77",
	"STRIPE_SECRET_KEY":     "sk_live_EXAMPLE",
}

var env = `APP_ENV=production
APP_URL=https://app.client-exemple.fr
ANTHROPIC_API_KEY=` + secrets["ANTHROPIC_API_KEY"] + `
GITLAB_TOKEN=` + secrets["GITLAB_TOKEN"] + `
AWS_ACCESS_KEY_ID=` + secrets["AWS_ACCESS_KEY_ID"] + `
DB_HOST=postgres.internal
DB_PASSWORD=` + secrets["DB_PASSWORD"] + `
SESSION_SECRET="` + secrets["SESSION_SECRET"] + `"
DATABASE_URL=postgres://app:` + secrets["DATABASE_URL_PASSWORD"] + `@postgres.internal:5432/app
STRIPE=` + secrets["STRIPE_SECRET_KEY"] + `
LOG_LEVEL=info
`

func testMasker() *Masker { return New([]byte("0123456789abcdef0123456789abcdef")) }

func maskOne(m *Masker, text string) (string, *Table) {
	t := m.NewTable()
	t.Learn(text)
	return t.Mask(text), t
}

func iban(country string, bban string) string {
	n := new(big.Int)
	digits := ""
	for _, r := range bban + country + "00" {
		if r >= 'A' && r <= 'Z' {
			digits += fmt.Sprint(int(r-'A') + 10)
		} else {
			digits += string(r)
		}
	}
	n.SetString(digits, 10)
	check := 98 - new(big.Int).Mod(n, big.NewInt(97)).Int64()
	raw := fmt.Sprintf("%s%02d%s", country, check, bban)
	var groups []string
	for i := 0; i < len(raw); i += 4 {
		groups = append(groups, raw[i:min(i+4, len(raw))])
	}
	return strings.Join(groups, " ")
}

func nir(body string) string {
	n := new(big.Int)
	n.SetString(body, 10)
	key := 97 - new(big.Int).Mod(n, big.NewInt(97)).Int64()
	return fmt.Sprintf("%s %s %s %s %s %s %02d", body[:1], body[1:3], body[3:5], body[5:7], body[7:10], body[10:13], key)
}

func dump(rows int) (string, []string) {
	rng := rand.New(rand.NewSource(1))
	first := []string{"Camille", "Julien", "Inès", "Thomas", "Léa", "Mehdi", "Chloé", "Zoé"}
	last := []string{"Durand", "Benali", "Lefèvre", "Nguyen", "Moreau", "Haddad", "Girard", "Fournier"}
	lines := []string{"INSERT INTO customers (id, first_name, last_name, email, phone, iban) VALUES"}
	var planted []string
	for i := range rows {
		f, l := first[rng.Intn(len(first))], last[rng.Intn(len(last))]
		email := fmt.Sprintf("%s.%s%d@mail-client.fr", strings.ToLower(f), strings.ToLower(l), i)
		phone := fmt.Sprintf("06 %02d %02d %02d %02d", rng.Intn(100), rng.Intn(100), rng.Intn(100), rng.Intn(100))
		account := iban("FR", fmt.Sprintf("%010d%011d%02d", rng.Int63n(1e10), rng.Int63n(1e11), rng.Intn(100)))
		planted = append(planted, email, phone, account)
		lines = append(lines, fmt.Sprintf("(%d, '%s', '%s', '%s', '%s', '%s'),", i, f, l, email, phone, account))
	}
	return strings.Join(lines, "\n"), planted
}

func TestEnvSecretsAreMasked(t *testing.T) {
	out, _ := maskOne(testMasker(), env)
	for name, value := range secrets {
		if strings.Contains(out, value) {
			t.Errorf("%s left in clear: %s", name, out)
		}
	}
	for _, kept := range []string{"APP_ENV=production", "DB_HOST=postgres.internal", "LOG_LEVEL=info", "postgres://app:"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q should stay readable in %s", kept, out)
		}
	}
}

func TestDumpPersonalDataIsMasked(t *testing.T) {
	text, planted := dump(300)
	out, _ := maskOne(testMasker(), text)
	leaked := 0
	for _, v := range planted {
		if strings.Contains(out, v) {
			leaked++
		}
	}
	if leaked != 0 {
		t.Fatalf("%d of %d values left in clear", leaked, len(planted))
	}
}

func TestProseIsMasked(t *testing.T) {
	social := nir("2850775123456")
	account := iban("DE", "370400440532013000")
	prose := "Mme Camille Durand (camille.durand@orange.fr, 06 12 34 56 78, +44 20 7946 0958) " +
		"a pour numéro " + social + " et son compte est " + account + ". Carte 4111 1111 1111 1111."
	out, _ := maskOne(testMasker(), prose)
	for _, v := range []string{"camille.durand@orange.fr", "06 12 34 56 78", "+44 20 7946 0958", social, account, "4111 1111 1111 1111"} {
		if strings.Contains(out, v) {
			t.Errorf("%q left in clear: %s", v, out)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	text, _ := dump(20)
	for _, in := range []string{env, text, "rien à masquer ici, version 1.2.3 et user@example.com"} {
		out, table := maskOne(testMasker(), in)
		if got := table.Unmask(out); got != in {
			t.Errorf("round trip changed the text:\n%s\n%s", in, got)
		}
	}
}

func TestSameValueSameToken(t *testing.T) {
	a, _ := maskOne(testMasker(), "DB_PASSWORD=Tr0ub4dor&3-horse")
	b, _ := maskOne(testMasker(), "DB_PASSWORD=Tr0ub4dor&3-horse")
	if a != b || !Placeholder.MatchString(a) {
		t.Fatalf("tokens differ or missing: %q %q", a, b)
	}
	other := New([]byte("another key of thirty two bytes!"))
	c, _ := maskOne(other, "DB_PASSWORD=Tr0ub4dor&3-horse")
	if c == a {
		t.Fatal("two machines share the same token")
	}
}

func TestRemaskKnownValue(t *testing.T) {
	m := testMasker()
	table := m.NewTable()
	table.Learn(env)
	code := `password = "Tr0ub4dor&3-horse"`
	table.Learn(code)
	if strings.Contains(table.Mask(code), "Tr0ub4dor&3-horse") {
		t.Fatal("a value seen in the .env is left in clear elsewhere")
	}
}

func TestEnvNameIsKept(t *testing.T) {
	_, table := maskOne(testMasker(), "DB_PASSWORD=Tr0ub4dor&3-horse\n")
	found := false
	for _, e := range table.Entries() {
		if e.Name == "DB_PASSWORD" && e.Kind == Secret {
			found = true
		}
	}
	if !found {
		t.Fatalf("variable name not recorded: %+v", table.Entries())
	}
}

func TestTechnicalAddressesStayReadable(t *testing.T) {
	text := "ssh root@db.zone-1.example.net && git clone git@git.example.com:team/tools/x.git && pnpm add react@19.0.0 && curl https://example.com/v1.2.3"
	out, _ := maskOne(testMasker(), text)
	if out != text {
		t.Fatalf("technical text was masked: %s", out)
	}
}

func TestUnmaskJSONEscapes(t *testing.T) {
	table := testMasker().NewTable()
	token := table.add(Secret, `quo"te\back`, "")
	if got := table.UnmaskJSON(`{"command":"echo ` + token + `"}`); got != `{"command":"echo quo\"te\\back"}` {
		t.Fatalf("value not escaped for JSON: %s", got)
	}
}

func TestFalsePositivesOnCode(t *testing.T) {
	root := filepath.Join(os.Getenv("HOME"), "Documents (Local)", "Workdir", "herse", "herse")
	if _, err := os.Stat(root); err != nil {
		t.Skip("herse checkout absent")
	}
	m := testMasker()
	var hits []string
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".py" {
			return nil
		}
		data, _ := os.ReadFile(path)
		for _, f := range m.find(string(data)) {
			hits = append(hits, fmt.Sprintf("%s %s %q", filepath.Base(path), f.Kind, string(data[max(0, f.Start-40):f.End])))
		}
		return nil
	})
	if len(hits) > 17 {
		t.Fatalf("%d detections on herse source code, at most 17 expected:\n%s", len(hits), strings.Join(hits, "\n"))
	}
}

func TestSecretsInToolOutputs(t *testing.T) {
	cases := map[string]string{
		"read tool":   "     1\tAPP_ENV=production\n     2\tDB_PASSWORD=Tr0ub4dor&3-horse\n",
		"old read":    "2→DB_PASSWORD=Tr0ub4dor&3-horse",
		"grep -rn":    "app/.env:2:DB_PASSWORD=Tr0ub4dor&3-horse",
		"grep -r":     "app/.env:DB_PASSWORD=Tr0ub4dor&3-horse",
		"compose":     "    environment:\n      - DB_PASSWORD=Tr0ub4dor&3-horse\n",
		"vault env":   "OVH_BILLS_CONSUMER_KEY=Tr0ub4dor&3-horse",
		"yaml":        "database:\n  password: Tr0ub4dor&3-horse\n",
		"json":        `{"user": "app", "db_password": "Tr0ub4dor&3-horse"}`,
		"python code": `DB_PASSWORD = "Tr0ub4dor&3-horse"`,
	}
	for name, text := range cases {
		out, _ := maskOne(testMasker(), text)
		if strings.Contains(out, "Tr0ub4dor&3-horse") {
			t.Errorf("%s: left in clear: %s", name, out)
		}
	}
}

func TestTemplatedValuesStayReadable(t *testing.T) {
	text := "password: ${DB_PASSWORD}\ntoken: {{ .Values.token }}\npassword = request.form[\"password\"]\n"
	out, _ := maskOne(testMasker(), text)
	if out != text {
		t.Fatalf("templating masked: %s", out)
	}
}
