package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	Label = "com.solyzon.privacy-gateway"
	Unit  = "privacy-gateway.service"
	Addr  = "127.0.0.1:8787"
)

type Service struct {
	Home     string
	UserHome string
	OS       string
	Run      func(name string, args ...string) ([]byte, error)
}

func Default() Service {
	home, _ := os.UserHomeDir()
	return Service{
		Home:     filepath.Join(home, ".solyzon", "privacy-gateway"),
		UserHome: home,
		OS:       runtime.GOOS,
		Run:      func(name string, args ...string) ([]byte, error) { return exec.Command(name, args...).CombinedOutput() },
	}
}

func (s Service) URL() string         { return "http://" + Addr }
func (s Service) Binary() string      { return filepath.Join(s.Home, "bin", "privacy-gateway") }
func (s Service) Settings() string    { return filepath.Join(s.UserHome, ".claude", "settings.json") }
func (s Service) StatusLog() string   { return filepath.Join(s.Home, "status.log") }
func (s Service) SessionsDir() string { return filepath.Join(s.Home, "sessions") }
func (s Service) CodexConfig() string { return filepath.Join(s.UserHome, ".codex", "config.toml") }
func (s Service) CodexUsed() bool {
	_, err := os.Stat(filepath.Join(s.UserHome, ".codex"))
	return err == nil
}
func (s Service) plistPath() string {
	return filepath.Join(s.UserHome, "Library", "LaunchAgents", Label+".plist")
}
func (s Service) unitPath() string {
	return filepath.Join(s.UserHome, ".config", "systemd", "user", Unit)
}
func (s Service) domain() string        { return fmt.Sprintf("gui/%d", os.Getuid()) }
func (s Service) launchdTarget() string { return s.domain() + "/" + Label }

func (s Service) Plist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + Label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + s.Binary() + `</string>
		<string>serve</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>ExitTimeOut</key>
	<integer>600</integer>
	<key>StandardErrorPath</key>
	<string>` + filepath.Join(s.Home, "stderr.log") + `</string>
</dict>
</plist>
`
}

func (s Service) UnitFile() string {
	return `[Unit]
Description=privacy-gateway, masking proxy in front of the Anthropic API

[Service]
ExecStart=` + s.Binary() + ` serve
Restart=always
RestartSec=1
TimeoutStopSec=600

[Install]
WantedBy=default.target
`
}

func sameFile(a, b string) bool {
	x, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	y, err := os.ReadFile(b)
	return err == nil && bytes.Equal(x, y)
}

func copyExecutable(dst string) (bool, error) {
	src, err := os.Executable()
	if err != nil {
		return false, err
	}
	if real, err := filepath.EvalSymlinks(src); err == nil {
		src = real
	}
	if src == dst || sameFile(src, dst) {
		return false, nil
	}
	in, err := os.Open(src)
	if err != nil {
		return false, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return false, err
	}
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return false, err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return false, err
	}
	if err := out.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, dst)
}

func Healthy(url string) bool {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url + "/healthz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitHealthy(url string) bool {
	for range 300 {
		if Healthy(url) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (s Service) Install() error {
	changed, err := copyExecutable(s.Binary())
	if err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	switch s.OS {
	case "darwin":
		if err := os.MkdirAll(filepath.Dir(s.plistPath()), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(s.plistPath(), []byte(s.Plist()), 0o644); err != nil {
			return err
		}
		if _, err := s.Run("launchctl", "print", s.launchdTarget()); err == nil {
			if changed {
				if out, err := s.Run("launchctl", "kill", "SIGTERM", s.launchdTarget()); err != nil {
					return fmt.Errorf("launchctl kill: %s", out)
				}
			}
		} else if out, err := s.Run("launchctl", "bootstrap", s.domain(), s.plistPath()); err != nil {
			return fmt.Errorf("launchctl bootstrap: %s", out)
		}
	case "linux":
		if err := os.MkdirAll(filepath.Dir(s.unitPath()), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(s.unitPath(), []byte(s.UnitFile()), 0o644); err != nil {
			return err
		}
		start := []string{"--user", "start", Unit}
		if changed {
			start = []string{"--user", "restart", Unit}
		}
		for _, args := range [][]string{{"--user", "daemon-reload"}, {"--user", "enable", Unit}, start} {
			if out, err := s.Run("systemctl", args...); err != nil {
				return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), out)
			}
		}
	default:
		return errors.New("unsupported system: " + s.OS)
	}
	if !waitHealthy(s.URL()) {
		return errors.New("the gateway does not answer on " + s.URL() + ", Claude Code settings left unchanged")
	}
	if err := SetBaseURL(s.Settings(), s.URL()); err != nil {
		return err
	}
	if s.CodexUsed() {
		if err := SetCodex(s.CodexConfig(), CodexBaseURL(s.URL(), filepath.Join(s.UserHome, ".codex", "auth.json"))); err != nil {
			return fmt.Errorf("Claude Code branché, Codex non : %w", err)
		}
	}
	return nil
}

func (s Service) Uninstall() error {
	if err := UnsetBaseURL(s.Settings(), s.URL()); err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	if err := UnsetCodex(s.CodexConfig()); err != nil {
		return fmt.Errorf("codex: %w", err)
	}
	switch s.OS {
	case "darwin":
		s.Run("launchctl", "bootout", s.launchdTarget())
		os.Remove(s.plistPath())
	case "linux":
		s.Run("systemctl", "--user", "disable", "--now", Unit)
		os.Remove(s.unitPath())
	}
	return nil
}

func (s Service) Running() (bool, string) {
	switch s.OS {
	case "darwin":
		out, err := s.Run("launchctl", "print", s.launchdTarget())
		if err != nil {
			return false, "agent launchd absent"
		}
		if strings.Contains(string(out), "state = running") {
			return true, "agent launchd actif"
		}
		return false, "agent launchd chargé mais arrêté"
	case "linux":
		out, _ := s.Run("systemctl", "--user", "is-active", Unit)
		state := strings.TrimSpace(string(out))
		return state == "active", "unité systemd " + state
	}
	return false, "système non pris en charge"
}
