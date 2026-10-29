package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

const BaseURLKey = "ANTHROPIC_BASE_URL"

type pair struct {
	key   string
	value json.RawMessage
}

func object(raw []byte) ([]pair, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("settings are not a JSON object")
	}
	var pairs []pair
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		pairs = append(pairs, pair{key: tok.(string), value: v})
	}
	return pairs, nil
}

func encodeObject(pairs []pair) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(p.key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(p.value)
	}
	b.WriteByte('}')
	return b.Bytes()
}

func set(pairs []pair, key string, value json.RawMessage) []pair {
	for i := range pairs {
		if pairs[i].key == key {
			pairs[i].value = value
			return pairs
		}
	}
	return append(pairs, pair{key: key, value: value})
}

func without(pairs []pair, key string) []pair {
	out := pairs[:0]
	for _, p := range pairs {
		if p.key != key {
			out = append(out, p)
		}
	}
	return out
}

func lookup(pairs []pair, key string) (json.RawMessage, bool) {
	for _, p := range pairs {
		if p.key == key {
			return p.value, true
		}
	}
	return nil, false
}

func readSettings(path string) ([]pair, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && len(bytes.TrimSpace(raw)) == 0) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return object(raw)
}

func writeSettings(path string, pairs []pair) error {
	var out bytes.Buffer
	if err := json.Indent(&out, encodeObject(pairs), "", "  "); err != nil {
		return err
	}
	out.WriteByte('\n')
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		real = path
	}
	mode := fs.FileMode(0o600)
	if info, err := os.Stat(real); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(real), ".settings-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	tmp.Chmod(mode)
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), real)
}

func BaseURL(path string) (string, error) {
	pairs, err := readSettings(path)
	if err != nil {
		return "", err
	}
	envRaw, ok := lookup(pairs, "env")
	if !ok {
		return "", nil
	}
	env, err := object(envRaw)
	if err != nil {
		return "", err
	}
	raw, ok := lookup(env, BaseURLKey)
	if !ok {
		return "", nil
	}
	var url string
	json.Unmarshal(raw, &url)
	return url, nil
}

func SetBaseURL(path, url string) error {
	pairs, err := readSettings(path)
	if err != nil {
		return err
	}
	var env []pair
	if raw, ok := lookup(pairs, "env"); ok {
		if env, err = object(raw); err != nil {
			return err
		}
	}
	value, _ := json.Marshal(url)
	env = set(env, BaseURLKey, value)
	return writeSettings(path, set(pairs, "env", encodeObject(env)))
}

func UnsetBaseURL(path, url string) error {
	current, err := BaseURL(path)
	if err != nil || current != url {
		return err
	}
	pairs, _ := readSettings(path)
	raw, _ := lookup(pairs, "env")
	env, _ := object(raw)
	env = without(env, BaseURLKey)
	if len(env) == 0 {
		pairs = without(pairs, "env")
	} else {
		pairs = set(pairs, "env", encodeObject(env))
	}
	return writeSettings(path, pairs)
}
