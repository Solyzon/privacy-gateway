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
`, []string{"Camille", "Durand", "Inès", "Lefèvre", "12 rue de la Paix", "3 bis avenue Foch"}, []string{"first_name", "Paris", "Lyon", "(2 rows)"}},
		{"mysql", `+----+----------------+---------------------------+
| id | name           | email                     |
+----+----------------+---------------------------+
|  7 | Thomas Moreau  | thomas@exemple-client.fr  |
+----+----------------+---------------------------+
`, []string{"Thomas Moreau"}, []string{"| id |"}},
		{"markdown", "| Nom | Prénom | Ville |\n|---|---|---|\n| Girard | Chloé | Nantes |\n", []string{"Girard", "Chloé"}, []string{"Nantes", "Prénom"}},
		{"csv", "id;nom;prenom;adresse;ville\n1;Fournier;Zoé;8 allée des Tilleuls;Rennes\n2;\"O'Neil\";Mehdi;\"5, place Bellecour\";Lyon\n", []string{"Fournier", "Zoé", "8 allée des Tilleuls", "O'Neil", "Mehdi", "5, place Bellecour"}, []string{"Rennes", "Lyon"}},
		{"read tool csv", "     1\tFirst Name,Last Name,Email\n     2\tJulien,Benali,julien@exemple-client.fr\n", []string{"Julien", "Benali"}, []string{"First Name"}},
		{"tsv", "first_name\tlast_name\nLéa\tHaddad\n", []string{"Léa", "Haddad"}, nil},
		{"copy", "COPY public.customers (id, first_name, last_name, street) FROM stdin;\n1\tCamille\tDurand\t12 rue de la Paix\n2\tZoé\t\\N\t\\N\n\\.\n", []string{"Camille", "Durand", "12 rue de la Paix", "Zoé"}, []string{"\\N"}},
		{"insert", "INSERT INTO customers (id, first_name, last_name) VALUES\n(1, 'Camille', 'Durand'),\n(2, 'Zoé', 'O''Neil');\n", []string{"Camille", "Durand", "Zoé", "O''Neil"}, []string{"INSERT INTO customers"}},
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
		{"json", `{"id": 3, "firstName": "Camille", "lastName": "Durand", "address": {"street": "12 rue de la Paix", "city": "Paris"}}`, []string{"Camille", "Durand", "12 rue de la Paix"}, []string{"Paris"}},
		{"json name with contact", `[{"name": "Camille Durand", "email": "camille@exemple-client.fr"}, {"name": "herse", "version": "1.2.0"}]`, []string{"Camille Durand"}, []string{`"name": "herse"`}},
		{"yaml", "customer:\n  first_name: Camille\n  last_name: Durand\n", []string{"Camille", "Durand"}, nil},
		{"sql", "UPDATE customers SET last_name = 'Durand' WHERE first_name = 'Camille';", []string{"Durand", "Camille"}, []string{"UPDATE customers SET last_name = "}},
		{"kwargs", `Customer(first_name="Camille", last_name="Durand", billing_address="12 rue de la Paix")`, []string{"Camille", "Durand", "12 rue de la Paix"}, nil},
		{"psql expanded", "-[ RECORD 1 ]-----------------------\nid    | 1\nname  | Camille Durand\nphone | 06 12 34 56 78\n-[ RECORD 2 ]-----------------------\nid    | 2\nname  | herse\n", []string{"Camille Durand"}, []string{"name  | herse"}},
	}
	for _, c := range cases {
		assertMasked(t, c.name, c.text, c.hidden, c.kept)
	}
}

func TestPersonalProseIsMasked(t *testing.T) {
	assertMasked(t, "letter", "Envoyer à Mme Camille Durand, 12 rue de la Paix, 75002 Paris, puis prévenir M. Octeau.",
		[]string{"Camille Durand", "12 rue de la Paix", "75002", "Octeau"}, []string{"Mme ", "M. "})
	assertMasked(t, "english", "Ship it to 221 Baker Street before Mr. Holmes calls.", []string{"221 Baker Street", "Holmes"}, []string{"Mr. "})
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
	out, table := maskOne(testMasker(), "first_name: Camille\nstreet: 12 rue de la Paix\n")
	if !strings.Contains(out, "SZ_NAME_") || !strings.Contains(out, "SZ_ADDRESS_") {
		t.Fatalf("got %s", out)
	}
	if back := table.Unmask(out); back != "first_name: Camille\nstreet: 12 rue de la Paix\n" {
		t.Fatalf("round trip %q", back)
	}
}
