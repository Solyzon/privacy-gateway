package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
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
	WantURL      string
	SettingsURL  func() (string, error)
	ProcessURL   string
	Running      func() (bool, string)
	Healthy      func() bool
	Connections  func() ([]Conn, error)
	AnthropicIPs func() ([]string, error)
	GatewayPID   string
	StatusLog    string
	Now          time.Time
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

	ips, err := e.AnthropicIPs()
	conns, err2 := e.Connections()
	if err != nil || err2 != nil {
		add("bypass", false, "connexions non vérifiées : %v %v", err, err2)
	} else {
		direct := map[string]bool{}
		known := map[string]bool{}
		for _, ip := range ips {
			known[ip] = true
		}
		for _, c := range conns {
			if known[c.Remote] && c.PID != e.GatewayPID {
				direct[fmt.Sprintf("%s (pid %s)", c.Command, c.PID)] = true
			}
		}
		if len(direct) == 0 {
			add("bypass", true, "aucun autre processus connecté à api.anthropic.com")
		} else {
			var names []string
			for n := range direct {
				names = append(names, n)
			}
			add("bypass", false, "connecté à api.anthropic.com sans passer par la passerelle : %s", strings.Join(names, ", "))
		}
	}

	total, failed := errorRate(e.StatusLog, e.Now.Add(-24*time.Hour))
	ok := total < 20 || failed*100 <= total
	add("errors", ok, "%d erreurs 400 ou 5xx sur %d requêtes de messages en 24 h", failed, total)
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
		if json.Unmarshal(scanner.Bytes(), &e) != nil || e.Path != "/v1/messages" {
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
