package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const codexConfig = `model = "gpt-5.6-terra"
model_reasoning_effort = "medium"

[features]
hooks = true

[projects."/tmp/x"]
trust_level = "trusted"
`

func TestSetAndUnsetCodex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(path, []byte(codexConfig), 0o644)
	if err := SetCodex(path, "http://127.0.0.1:8787/codex"); err != nil {
		t.Fatal(err)
	}
	if err := SetCodex(path, "http://127.0.0.1:8787/codex"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(got), `model_provider = "privacy-gateway"`+"\n"+`model = "gpt-5.6-terra"`) || strings.Count(string(got), "[model_providers.privacy-gateway]") != 1 || !strings.Contains(string(got), "trust_level = \"trusted\"\n\n[model_providers.privacy-gateway]") {
		t.Fatalf("got\n%s", got)
	}
	provider, base, _ := CodexState(path)
	if provider != CodexProvider || base != "http://127.0.0.1:8787/codex" {
		t.Fatalf("state %q %q", provider, base)
	}
	if err := UnsetCodex(path); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != codexConfig {
		t.Fatalf("not restored:\n%s", got)
	}
}

func TestOtherCodexProviderIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(path, []byte("model_provider = \"ollama\"\n"), 0o600)
	if err := SetCodex(path, "http://127.0.0.1:8787/codex"); err == nil {
		t.Fatal("foreign provider overwritten")
	}
}

func TestCodexBaseURLFollowsAuthMode(t *testing.T) {
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.json")
	os.WriteFile(auth, []byte(`{"auth_mode":"chatgpt"}`), 0o600)
	if got := CodexBaseURL("http://127.0.0.1:8787", auth); got != "http://127.0.0.1:8787/codex" {
		t.Fatal(got)
	}
	if got := CodexBaseURL("http://127.0.0.1:8787", filepath.Join(dir, "absent")); got != "http://127.0.0.1:8787/openai/v1" {
		t.Fatal(got)
	}
}
