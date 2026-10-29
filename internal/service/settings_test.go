package service

import (
	"os"
	"path/filepath"
	"testing"
)

const original = `{
  "zeta": {"b": 1, "a": "café"},
  "env": {
    "OTHER": "x"
  },
  "alpha": [1, 2]
}
`

func TestSetAndUnsetKeepTheRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte(original), 0o644)
	if err := SetBaseURL(path, "http://127.0.0.1:8787"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	want := `{
  "zeta": {
    "b": 1,
    "a": "café"
  },
  "env": {
    "OTHER": "x",
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"
  },
  "alpha": [
    1,
    2
  ]
}
`
	if string(got) != want {
		t.Fatalf("got\n%s", got)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode changed: %v", info.Mode())
	}
	if url, _ := BaseURL(path); url != "http://127.0.0.1:8787" {
		t.Fatalf("read back %q", url)
	}
	if err := UnsetBaseURL(path, "http://127.0.0.1:8787"); err != nil {
		t.Fatal(err)
	}
	if url, _ := BaseURL(path); url != "" {
		t.Fatalf("still set: %q", url)
	}
}

func TestUnsetLeavesAnotherURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte(`{"env":{"ANTHROPIC_BASE_URL":"https://proxy.example"}}`), 0o600)
	UnsetBaseURL(path, "http://127.0.0.1:8787")
	if url, _ := BaseURL(path); url != "https://proxy.example" {
		t.Fatalf("foreign value removed: %q", url)
	}
}

func TestMissingFileIsCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude", "settings.json")
	if err := SetBaseURL(path, "http://127.0.0.1:8787"); err != nil {
		t.Fatal(err)
	}
	if url, _ := BaseURL(path); url != "http://127.0.0.1:8787" {
		t.Fatalf("got %q", url)
	}
}

func TestBrokenSettingsAreNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(path, []byte(`{"env": `), 0o600)
	if err := SetBaseURL(path, "http://127.0.0.1:8787"); err == nil {
		t.Fatal("broken settings accepted")
	}
	if got, _ := os.ReadFile(path); string(got) != `{"env": ` {
		t.Fatal("broken settings overwritten")
	}
}
