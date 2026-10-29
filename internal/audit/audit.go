package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Finding struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type Conn struct {
	PID     string
	Command string
	Remote  string
}

type Env struct {
	WantURL       string
	SettingsURL   func() (string, error)
	ProcessURL    string
	Running       func() (bool, string)
	Healthy       func() bool
	Connections   func() ([]Conn, error)
	AnthropicIPs  func() ([]string, error)
	OpenAIIPs     func() ([]string, error)
	Codex         func() (used bool, provider string)
	GatewayPID    string
	StatusLog     string
	Now           time.Time
	ClaudeSession func(pid string) (id string, started time.Time, ok bool)
}

func Run(e Env) []Finding {
	var out []Finding
	add := func(check string, ok bool, format string, args ...any) {
		out = append(out, Finding{Check: check, OK: ok, Detail: fmt.Sprintf(format, args...)})
	}

	running, state := e.Running()
	add("service", running, "%s", state)
	add("healthz", e.Healthy(), "réponse et canari de %s/healthz", e.WantURL)

	url, err := e.SettingsURL()
	switch {
	case err != nil:
		add("settings", false, "~/.claude/settings.json illisible : %v", err)
	case url != e.WantURL:
		add("settings", false, "ANTHROPIC_BASE_URL vaut %q dans ~/.claude/settings.json, %q attendu", url, e.WantURL)
	default:
		add("settings", true, "ANTHROPIC_BASE_URL pointe sur la passerelle")
	}
	if e.ProcessURL != "" && e.ProcessURL != e.WantURL {
		add("shell", false, "ANTHROPIC_BASE_URL vaut %q dans l'environnement du shell, qui passe avant les réglages", e.ProcessURL)
	}

	if used, provider := e.Codex(); used {
		add("codex", provider == "privacy-gateway", "model_provider de ~/.codex/config.toml : %q, \"privacy-gateway\" attendu", provider)
	}

	anthropic, err := e.AnthropicIPs()
	openai, err2 := e.OpenAIIPs()
	conns, err3 := e.Connections()
	if err != nil || err2 != nil || err3 != nil {
		add("bypass", false, "connexions non vérifiées : %v %v %v", err, err2, err3)
	} else {
		toAnthropic := set(anthropic)
		toOpenAI := set(openai)
		seen := sessionsSeen(e.StatusLog)
		direct, browsers, routed := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, c := range conns {
			if c.PID == e.GatewayPID {
				continue
			}
			codex := strings.Contains(strings.ToLower(c.Command), "codex")
			if !toAnthropic[c.Remote] && !(codex && toOpenAI[c.Remote]) {
				continue
			}
			if browser.MatchString(c.Command) {
				browsers[c.Command] = true
				continue
			}
			label := c.Command
			if version.MatchString(label) {
				if id, started, ok := e.ClaudeSession(c.PID); ok && !seen[id].Before(started) {
					routed[c.PID] = true
					continue
				}
				label = "Claude Code " + label
			}
			direct[fmt.Sprintf("%s (pid %s)", label, c.PID)] = true
		}
		outside := ""
		if len(browsers) > 0 {
			outside = ", navigateur hors périmètre : " + strings.Join(sorted(browsers), ", ")
		}
		switch n := len(routed); {
		case n == 1:
			outside = ", 1 session de Claude Code passe par elle et garde une liaison directe hors messages (compte, télémétrie)" + outside
		case n > 1:
			outside = fmt.Sprintf(", %d sessions de Claude Code passent par elle et gardent une liaison directe hors messages (compte, télémétrie)%s", n, outside)
		}
		if len(direct) == 0 {
			add("bypass", true, "aucun agent ne parle à Anthropic ou à OpenAI sans la passerelle%s", outside)
		} else {
			add("bypass", false, "en direct, sans la passerelle : %s ; une session ouverte avant l'installation se relance, une session neuve passe en règle à son premier message%s", strings.Join(sorted(direct), ", "), outside)
		}
	}

	total, failed := errorRate(e.StatusLog, e.Now.Add(-24*time.Hour))
	ok := total < 20 || failed*100 <= total
	add("errors", ok, "%d erreurs 400 ou 5xx sur %d requêtes de messages ou de réponses en 24 h", failed, total)
	return out
}

var (
	browser = regexp.MustCompile(`(?i)chrome|safari|firefox|arc|brave|edge|opera|vivaldi|webkit|orion`)
	version = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

func set(values []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		out[v] = true
	}
	return out
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sessionsSeen(path string) map[string]time.Time {
	out := map[string]time.Time{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e struct {
			Time    string `json:"time"`
			Session string `json:"session"`
		}
		if json.Unmarshal(scanner.Bytes(), &e) != nil || e.Session == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil && t.After(out[e.Session]) {
			out[e.Session] = t
		}
	}
	return out
}

func errorRate(path string, since time.Time) (total, failed int) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e struct {
			Time   string `json:"time"`
			Path   string `json:"path"`
			Status int    `json:"status"`
		}
		if json.Unmarshal(scanner.Bytes(), &e) != nil || (e.Path != "/v1/messages" && !strings.HasSuffix(e.Path, "/responses")) {
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.Time); err != nil || t.Before(since) {
			continue
		}
		total++
		if e.Status == 400 || e.Status >= 500 {
			failed++
		}
	}
	return total, failed
}

func ParseLsof(out string) []Conn {
	var conns []Conn
	var pid, command string
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid = line[1:]
		case 'c':
			command = line[1:]
		case 'n':
			arrow := strings.Index(line, "->")
			if arrow < 0 {
				continue
			}
			remote := line[arrow+2:]
			host := remote[:strings.LastIndex(remote, ":")]
			conns = append(conns, Conn{PID: pid, Command: command, Remote: strings.Trim(host, "[]")})
		}
	}
	return conns
}
