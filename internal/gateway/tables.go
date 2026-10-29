package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Solyzon/privacy-gateway/internal/body"
	"github.com/Solyzon/privacy-gateway/internal/mask"
)

const (
	tableMaxAge   = 30 * 24 * time.Hour
	tableCacheCap = 200
)

type cachedTable struct {
	records map[string]mask.Record
	used    time.Time
}

type tables struct {
	mu    sync.Mutex
	dir   string
	aead  cipher.AEAD
	cache map[string]*cachedTable
}

func newTables(dir string, key []byte) (*tables, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("privacy-gateway session tables v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	t := &tables{dir: dir, aead: aead, cache: map[string]*cachedTable{}}
	t.prune()
	return t, nil
}

func (t *tables) prune() {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > tableMaxAge {
			os.Remove(filepath.Join(t.dir, e.Name()))
		}
	}
}

func sessionKey(r *http.Request, raw []byte) string {
	for _, id := range []string{r.Header.Get("X-Claude-Code-Session-Id"), r.Header.Get("Session-Id"), body.SessionID(raw)} {
		if validSession.MatchString(id) {
			return id
		}
	}
	return ""
}

func (t *tables) path(id string) string { return filepath.Join(t.dir, id+".bin") }

func (t *tables) read(id string) map[string]mask.Record {
	out := map[string]mask.Record{}
	sealed, err := os.ReadFile(t.path(id))
	if err != nil || len(sealed) < t.aead.NonceSize() {
		return out
	}
	nonce, data := sealed[:t.aead.NonceSize()], sealed[t.aead.NonceSize():]
	plain, err := t.aead.Open(nil, nonce, data, []byte(id))
	if err != nil {
		return out
	}
	var records []mask.Record
	if json.Unmarshal(plain, &records) == nil {
		for _, r := range records {
			out[r.Value] = r
		}
	}
	return out
}

func (t *tables) entry(id string) *cachedTable {
	if c, ok := t.cache[id]; ok {
		c.used = time.Now()
		return c
	}
	if len(t.cache) >= tableCacheCap {
		oldest, at := "", time.Now()
		for k, c := range t.cache {
			if c.used.Before(at) {
				oldest, at = k, c.used
			}
		}
		delete(t.cache, oldest)
	}
	c := &cachedTable{records: t.read(id), used: time.Now()}
	t.cache[id] = c
	return c
}

func (t *tables) Load(id string) []mask.Record {
	if id == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.entry(id)
	out := make([]mask.Record, 0, len(c.records))
	for _, r := range c.records {
		out = append(out, r)
	}
	return out
}

func (t *tables) Save(id string, records []mask.Record) error {
	if id == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.entry(id)
	for _, r := range records {
		c.records[r.Value] = r
	}
	all := make([]mask.Record, 0, len(c.records))
	for _, r := range c.records {
		all = append(all, r)
	}
	plain, err := json.Marshal(all)
	if err != nil {
		return err
	}
	nonce := make([]byte, t.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := os.MkdirAll(t.dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(t.dir, "."+id+".tmp")
	if err := os.WriteFile(tmp, t.aead.Seal(nonce, nonce, plain, []byte(id)), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.path(id)); err != nil {
		return errors.Join(err, os.Remove(tmp))
	}
	return nil
}
