package mask

import (
	"strings"
	"testing"
)

func assertMasked(t *testing.T, name, text string, hidden, kept []string) {
	t.Helper()
	out, _ := maskOne(testMasker(), text)
	for _, v := range hidden {
		if strings.Contains(out, v) {
			t.Errorf("%s: %q left in clear:\n%s", name, v, out)
		}
	}
	for _, v := range kept {
		if !strings.Contains(out, v) {
			t.Errorf("%s: %q should stay readable:\n%s", name, v, out)
		}
	}
}

func TestPersonalColumnsAreMasked(t *testing.T) {
	cases := []struct {
		name, text   string
		hidden, kept []string
	}{
		{"psql", ` id | first_name | last_name |      address       | city
----+------------+-----------+--------------------+-------
  1 | Camille    | Durand    | 12 rue de la Paix  | Paris
  2 | Inès       | Lefèvre   | 3 bis avenue Foch  | Lyon
(2 rows)
`, []string{"12 rue de la Paix", "3 bis avenue Foch"}, []string{"first_name", "Paris", "Lyon", "(2 rows)", "Camille", "Durand", "Inès", "Lefèvre"}},
		{"mysql", `+----+----------------+---------------------------+
| id | name           | email                     |
+----+----------------+---------------------------+
|  7 | Thomas Moreau  | thomas@exemple-client.fr  |
+----+----------------+---------------------------+
`, nil, []string{"| id |", "Thomas Moreau"}},
		{"markdown", "| Nom | Prénom | Ville |\n|---|---|---|\n| Girard | Chloé | Nantes |\n", nil, []string{"Nantes", "Prénom", "Girard", "Chloé"}},
		{"csv", "id;nom;prenom;adresse;ville\n1;Fournier;Zoé;8 allée des Tilleuls;Rennes\n2;\"O'Neil\";Mehdi;\"5, place Bellecour\";Lyon\n", []string{"8 allée des Tilleuls", "5, place Bellecour"}, []string{"Rennes", "Lyon", "Fournier", "Zoé", "O'Neil", "Mehdi"}},
		{"read tool csv", "     1\tFirst Name,Last Name,Email\n     2\tJulien,Benali,julien@exemple-client.fr\n", nil, []string{"First Name", "Julien", "Benali"}},
		{"tsv", "first_name\tlast_name\nLéa\tHaddad\n", nil, []string{"Léa", "Haddad"}},
		{"copy", "COPY public.customers (id, first_name, last_name, street) FROM stdin;\n1\tCamille\tDurand\t12 rue de la Paix\n2\tZoé\t\\N\t\\N\n\\.\n", []string{"12 rue de la Paix"}, []string{"\\N", "Camille", "Durand", "Zoé"}},
		{"insert", "INSERT INTO customers (id, first_name, last_name) VALUES\n(1, 'Camille', 'Durand'),\n(2, 'Zoé', 'O''Neil');\n", nil, []string{"INSERT INTO customers", "Camille", "Durand", "Zoé", "O''Neil"}},
	}
	for _, c := range cases {
		assertMasked(t, c.name, c.text, c.hidden, c.kept)
	}
}

func TestPersonalFieldsAreMasked(t *testing.T) {
	cases := []struct {
		name, text   string
		hidden, kept []string
	}{
		{"json", `{"id": 3, "firstName": "Camille", "lastName": "Durand", "address": {"street": "12 rue de la Paix", "city": "Paris"}}`, []string{"12 rue de la Paix"}, []string{"Paris", "Camille", "Durand"}},
		{"json name with contact", `[{"name": "Camille Durand", "email": "camille@exemple-client.fr"}, {"name": "herse", "version": "1.2.0"}]`, nil, []string{`"name": "herse"`, "Camille Durand"}},
		{"yaml", "customer:\n  first_name: Camille\n  last_name: Durand\n", nil, []string{"Camille", "Durand"}},
		{"sql", "UPDATE customers SET last_name = 'Durand' WHERE first_name = 'Camille';", nil, []string{"UPDATE customers SET last_name = ", "Durand", "Camille"}},
		{"kwargs", `Customer(first_name="Camille", last_name="Durand", billing_address="12 rue de la Paix")`, []string{"12 rue de la Paix"}, []string{"Camille", "Durand"}},
		{"psql expanded", "-[ RECORD 1 ]-----------------------\nid    | 1\nname  | Camille Durand\nphone | 06 12 34 56 78\n-[ RECORD 2 ]-----------------------\nid    | 2\nname  | herse\n", nil, []string{"name  | herse", "Camille Durand"}},
	}
	for _, c := range cases {
		assertMasked(t, c.name, c.text, c.hidden, c.kept)
	}
}

func TestPersonalProseIsMasked(t *testing.T) {
	assertMasked(t, "letter", "Envoyer à Mme Camille Durand, 12 rue de la Paix, 75002 Paris, puis prévenir M. Octeau.",
		[]string{"12 rue de la Paix", "75002"}, []string{"Mme ", "M. ", "Camille Durand", "Octeau"})
	assertMasked(t, "english", "Ship it to 221 Baker Street before Mr. Holmes calls.", []string{"221 Baker Street"}, []string{"Mr. ", "Holmes"})
}

func TestPersonalLookalikesStayReadable(t *testing.T) {
	text := `class Customer(BaseModel):
    first_name: str
    last_name: Optional[str] = None
    """Args:
        first_name: The user's first name.
        address: The address to bind to.
    """
first_name = form.cleaned_data["first_name"]
firstName: string;
{"firstName": "string", "lastName": "required"}
server:
  address: 0.0.0.0:8080
  name: herse
display_name="Herse"
filename = "Report Final.pdf"
replace 2 place holders, le 3 mai, page 4 Section B
 nom | ville
-----+-------
`
	out, _ := maskOne(testMasker(), text)
	if out != text {
		t.Fatalf("code masked:\n%s", out)
	}
}

func TestPersonalTokensHaveTheirKind(t *testing.T) {
	text := "street: 12 rue de la Paix, 75002 Paris\n"
	out, table := maskOne(testMasker(), text)
	if !strings.Contains(out, "SZ_ADDRESS_") || strings.Contains(out, "rue de la Paix") {
		t.Fatalf("got %s", out)
	}
	if back := table.Unmask(out); back != text {
		t.Fatalf("round trip %q", back)
	}
}

func TestNamesAreNeverMasked(t *testing.T) {
	text := "first_name: Victor\nMme Dupont a écrit à M. Martin\nDB_PASSWORD=hunter2hunter2\n"
	out, _ := maskOne(testMasker(), text)
	for _, v := range []string{"Victor", "Dupont", "Martin"} {
		if !strings.Contains(out, v) {
			t.Errorf("%q masked:\n%s", v, out)
		}
	}
	if strings.Contains(out, "SZ_NAME_") || strings.Contains(out, "hunter2hunter2") {
		t.Fatalf("name token or secret in clear:\n%s", out)
	}
}
