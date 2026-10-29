package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const CodexProvider = "privacy-gateway"

var (
	tomlHeader       = regexp.MustCompile(`^\s*\[`)
	topModelProvider = regexp.MustCompile(`^\s*model_provider\s*=\s*"([^"]*)"\s*$`)
	ourTable         = regexp.MustCompile(`^\s*\[\s*model_providers\.(?:"privacy-gateway"|privacy-gateway)\s*\]\s*$`)
	ourBaseURL       = regexp.MustCompile(`^\s*base_url\s*=\s*"([^"]*)"\s*$`)
)

func codexBlock(baseURL string) []string {
	return []string{
		"[model_providers." + CodexProvider + "]",
		`name = "OpenAI via privacy-gateway"`,
		`base_url = "` + baseURL + `"`,
		`wire_api = "responses"`,
		`requires_openai_auth = true`,
	}
}

func CodexBaseURL(gateway, authPath string) string {
	var auth struct {
		Mode string `json:"auth_mode"`
	}
	if raw, err := os.ReadFile(authPath); err == nil {
		json.Unmarshal(raw, &auth)
	}
	if auth.Mode == "chatgpt" {
		return gateway + "/codex"
	}
	return gateway + "/openai/v1"
}

func readLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	text := strings.TrimRight(string(raw), "\n")
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

func topLevelEnd(lines []string) int {
	for i, l := range lines {
		if tomlHeader.MatchString(l) {
			return i
		}
	}
	return len(lines)
}

func withoutOurTable(lines []string) []string {
	var out []string
	skip := false
	for _, l := range lines {
		if tomlHeader.MatchString(l) {
			skip = ourTable.MatchString(l)
		}
		if !skip {
			out = append(out, l)
		}
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}

func writeLines(path string, lines []string) error {
	text := strings.Join(lines, "\n") + "\n"
	mode := fs.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".privacy-gateway.tmp"
	if err := os.WriteFile(tmp, []byte(text), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func CodexState(path string) (provider, baseURL string, err error) {
	lines, err := readLines(path)
	if err != nil {
		return "", "", err
	}
	for _, l := range lines[:topLevelEnd(lines)] {
		if m := topModelProvider.FindStringSubmatch(l); m != nil {
			provider = m[1]
		}
	}
	in := false
	for _, l := range lines {
		if tomlHeader.MatchString(l) {
			in = ourTable.MatchString(l)
			continue
		}
		if m := ourBaseURL.FindStringSubmatch(l); in && m != nil {
			baseURL = m[1]
		}
	}
	return provider, baseURL, nil
}

func SetCodex(path, baseURL string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	end := topLevelEnd(lines)
	found := false
	for _, l := range lines[:end] {
		if m := topModelProvider.FindStringSubmatch(l); m != nil {
			if m[1] != CodexProvider {
				return fmt.Errorf("model_provider vaut déjà %q dans %s, laissé tel quel", m[1], path)
			}
			found = true
		}
	}
	if !found {
		lines = append([]string{`model_provider = "` + CodexProvider + `"`}, lines...)
	}
	lines = withoutOurTable(lines)
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	return writeLines(path, append(lines, codexBlock(baseURL)...))
}

func UnsetCodex(path string) error {
	lines, err := readLines(path)
	if err != nil || lines == nil {
		return err
	}
	end := topLevelEnd(lines)
	var out []string
	for i, l := range lines {
		if m := topModelProvider.FindStringSubmatch(l); i < end && m != nil && m[1] == CodexProvider {
			continue
		}
		out = append(out, l)
	}
	return writeLines(path, withoutOurTable(out))
}
