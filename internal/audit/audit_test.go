package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const want = "http://127.0.0.1:8787"

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func healthy(t *testing.T) Env {
	return Env{
		WantURL:     want,
		SettingsURL: func() (string, error) { return want, nil },
		Running:     func() (bool, string) { return true, "agent launchd actif" },
		Healthy:     func() bool { return true },
		Connections: func() ([]Conn, error) {
			return []Conn{{PID: "10", Command: "privacy-gateway", Remote: "160.79.104.10"}}, nil
		},
		AnthropicIPs: func() ([]string, error) { return []string{"160.79.104.10"}, nil },
		GatewayPID:   "10",
		StatusLog:    filepath.Join(t.TempDir(), "status.log"),
		Now:          now,
	}
}

func failing(findings []Finding) []string {
	var out []string
	for _, f := range findings {
		if !f.OK {
			out = append(out, f.Check)
		}
	}
	return out
}

func TestHealthyMachineHasNoFinding(t *testing.T) {
	if f := failing(Run(healthy(t))); len(f) != 0 {
		t.Fatalf("unexpected findings %v", f)
	}
}

func TestEachHoleIsReported(t *testing.T) {
	cases := map[string]func(*Env){
		"service":  func(e *Env) { e.Running = func() (bool, string) { return false, "agent launchd absent" } },
		"healthz":  func(e *Env) { e.Healthy = func() bool { return false } },
		"settings": func(e *Env) { e.SettingsURL = func() (string, error) { return "", nil } },
		"shell":    func(e *Env) { e.ProcessURL = "https://api.anthropic.com" },
		"bypass": func(e *Env) {
			e.Connections = func() ([]Conn, error) {
				return []Conn{{PID: "10", Command: "privacy-gateway", Remote: "160.79.104.10"}, {PID: "99", Command: "node", Remote: "160.79.104.10"}}, nil
			}
		},
		"errors": func(e *Env) {
			var lines []string
			for i := range 40 {
				status := 200
				if i%10 == 0 {
					status = 400
				}
				lines = append(lines, fmt.Sprintf(`{"time":"%s","path":"/v1/messages","status":%d}`, now.Add(-time.Hour).Format(time.RFC3339), status))
			}
			os.WriteFile(e.StatusLog, []byte(strings.Join(lines, "\n")), 0o600)
		},
	}
	for check, breakIt := range cases {
		e := healthy(t)
		breakIt(&e)
		if f := failing(Run(e)); len(f) != 1 || f[0] != check {
			t.Errorf("%s: findings %v", check, f)
		}
	}
}

func TestOldErrorsAreIgnored(t *testing.T) {
	e := healthy(t)
	var lines []string
	for range 40 {
		lines = append(lines, fmt.Sprintf(`{"time":"%s","path":"/v1/messages","status":500}`, now.Add(-48*time.Hour).Format(time.RFC3339)))
	}
	os.WriteFile(e.StatusLog, []byte(strings.Join(lines, "\n")), 0o600)
	if f := failing(Run(e)); len(f) != 0 {
		t.Fatalf("old errors reported: %v", f)
	}
}

func TestParseLsof(t *testing.T) {
	out := "p10\ncprivacy-gateway\nf7\nn127.0.0.1:50000->160.79.104.10:443\np22\ncnode\nf9\nn[2001:db8::1]:5000->[2607:6bc0::10]:443\n"
	conns := ParseLsof(out)
	if len(conns) != 2 || conns[0] != (Conn{"10", "privacy-gateway", "160.79.104.10"}) || conns[1] != (Conn{"22", "node", "2607:6bc0::10"}) {
		t.Fatalf("got %+v", conns)
	}
}
