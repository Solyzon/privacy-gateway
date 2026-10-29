package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Solyzon/privacy-gateway/internal/body"
	"github.com/Solyzon/privacy-gateway/internal/mask"
)

const (
	sessionLimit  = 500
	noticeMaxAge  = 7 * 24 * time.Hour
	sessionPrefix = "masqué : "
)

var validSession = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

var labels = map[mask.Kind][2]string{
	mask.Secret: {"secret", "secrets"},
	mask.Email:  {"e-mail", "e-mails"},
	mask.Phone:  {"téléphone", "téléphones"},
	mask.IBAN:   {"IBAN", "IBAN"},
	mask.NIR:    {"n° de sécurité sociale", "n° de sécurité sociale"},
	mask.Card:   {"carte bancaire", "cartes bancaires"},
}

var labelOrder = []mask.Kind{mask.Secret, mask.Email, mask.Phone, mask.IBAN, mask.NIR, mask.Card}

type sessions struct {
	mu   sync.Mutex
	dir  string
	seen map[string]map[string]bool
	used map[string]time.Time
}

func newSessions(dir string) *sessions {
	s := &sessions{dir: dir, seen: map[string]map[string]bool{}, used: map[string]time.Time{}}
	s.prune()
	return s
}

func (s *sessions) prune() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > noticeMaxAge {
			os.Remove(filepath.Join(s.dir, e.Name()))
		}
	}
}

func describe(entries []mask.Entry) string {
	var names []string
	count := map[mask.Kind]int{}
	for _, e := range entries {
		if e.Name != "" {
			names = append(names, e.Name)
		} else {
			count[e.Kind]++
		}
	}
	parts := names
	for _, k := range labelOrder {
		if n := count[k]; n > 0 {
			label := labels[k][0]
			if n > 1 {
				label = labels[k][1]
			}
			parts = append(parts, fmt.Sprintf("%d %s", n, label))
		}
	}
	return sessionPrefix + strings.Join(parts, ", ")
}

func describeFiles(count map[string]int) string {
	var parts []string
	for _, k := range []string{"PDF", "image", "fichier"} {
		n := count[k]
		if n == 0 {
			continue
		}
		label := k
		if n > 1 && k != "PDF" {
			label += "s"
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, label))
	}
	return "non masqué : " + strings.Join(parts, ", ")
}

func (s *sessions) notice(id string, entries []mask.Entry, files []body.Attachment) {
	if !validSession.MatchString(id) || (len(entries) == 0 && len(files) == 0) {
		return
	}
	s.mu.Lock()
	seen := s.seen[id]
	if seen == nil {
		if len(s.seen) >= sessionLimit {
			oldest, at := "", time.Now()
			for k, t := range s.used {
				if t.Before(at) {
					oldest, at = k, t
				}
			}
			delete(s.seen, oldest)
			delete(s.used, oldest)
		}
		seen = map[string]bool{}
		s.seen[id] = seen
	}
	s.used[id] = time.Now()
	var fresh []mask.Entry
	for _, e := range entries {
		if !seen[e.Token] {
			seen[e.Token] = true
			fresh = append(fresh, e)
		}
	}
	clear := map[string]int{}
	for _, f := range files {
		if !seen["file:"+f.Hash] {
			seen["file:"+f.Hash] = true
			clear[f.Kind]++
		}
	}
	s.mu.Unlock()
	var parts []string
	if len(fresh) > 0 {
		parts = append(parts, describe(fresh))
	}
	if len(clear) > 0 {
		parts = append(parts, describeFiles(clear))
	}
	if len(parts) == 0 {
		return
	}
	payload, _ := json.Marshal(map[string]any{"time": time.Now().UnixMilli(), "text": strings.Join(parts, " · ")})
	if os.MkdirAll(s.dir, 0o700) != nil {
		return
	}
	tmp := filepath.Join(s.dir, "."+id+".tmp")
	if os.WriteFile(tmp, payload, 0o600) == nil {
		os.Rename(tmp, filepath.Join(s.dir, id+".json"))
	}
}
