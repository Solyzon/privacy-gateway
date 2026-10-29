package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Solyzon/privacy-gateway/internal/audit"
	"github.com/Solyzon/privacy-gateway/internal/gateway"
	"github.com/Solyzon/privacy-gateway/internal/service"
)

var version = "0.1.0"

const usage = `privacy-gateway serve | install | uninstall | status | audit [--json] | notice --session <id> | version`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	svc := service.Default()
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(svc, os.Args[2:])
	case "install":
		err = svc.Install()
		if err == nil {
			fmt.Println("installé, Claude Code passe par " + svc.URL())
			if provider, base, _ := service.CodexState(svc.CodexConfig()); provider == service.CodexProvider {
				fmt.Println("Codex passe par " + base)
			}
		}
	case "uninstall":
		err = svc.Uninstall()
		if err == nil {
			fmt.Println("désinstallé, Claude Code et Codex parlent de nouveau directement à leur fournisseur")
		}
	case "status":
		running, state := svc.Running()
		url, _ := service.BaseURL(svc.Settings())
		fmt.Printf("service   %s\nhealthz   %v\nréglage   ANTHROPIC_BASE_URL=%s\n", state, running && service.Healthy(svc.URL()), url)
	case "audit":
		os.Exit(runAudit(svc, os.Args[2:]))
	case "notice":
		notice(svc, os.Args[2:])
	case "version":
		fmt.Println("privacy-gateway " + version)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "privacy-gateway: "+err.Error())
		os.Exit(1)
	}
}

func serve(svc service.Service, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", service.Addr, "listen address")
	upstream := fs.String("upstream", "https://api.anthropic.com", "Anthropic API")
	home := fs.String("home", svc.Home, "state folder")
	fs.Parse(args)
	g, err := gateway.New(gateway.Config{Upstream: *upstream, Home: *home, Version: version})
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(*addr)
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("the gateway only listens on a loopback address")
	}
	server := &http.Server{Addr: *addr, Handler: g, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		server.Shutdown(drain)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runAudit(svc service.Service, args []string) int {
	asJSON := len(args) > 0 && args[0] == "--json"
	lsof := func(args ...string) (string, error) {
		out, err := exec.Command("lsof", args...).Output()
		if err != nil && len(out) == 0 {
			if _, look := exec.LookPath("lsof"); look != nil {
				return "", look
			}
		}
		return string(out), nil
	}
	_, port, _ := net.SplitHostPort(service.Addr)
	pidOut, _ := lsof("-nP", "-iTCP:"+port, "-sTCP:LISTEN", "-t")
	findings := audit.Run(audit.Env{
		WantURL:     svc.URL(),
		SettingsURL: func() (string, error) { return service.BaseURL(svc.Settings()) },
		ProcessURL:  os.Getenv(service.BaseURLKey),
		Running:     svc.Running,
		Healthy:     func() bool { return service.Healthy(svc.URL()) },
		Connections: func() ([]audit.Conn, error) {
			out, err := lsof("-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn")
			return audit.ParseLsof(out), err
		},
		AnthropicIPs: func() ([]string, error) { return net.LookupHost("api.anthropic.com") },
		OpenAIIPs: func() ([]string, error) {
			var all []string
			for _, host := range []string{"api.openai.com", "chatgpt.com"} {
				ips, err := net.LookupHost(host)
				if err != nil {
					return nil, err
				}
				all = append(all, ips...)
			}
			return all, nil
		},
		Codex: func() (bool, string) {
			provider, _, _ := service.CodexState(svc.CodexConfig())
			return svc.CodexUsed(), provider
		},
		GatewayPID: strings.TrimSpace(pidOut),
		StatusLog:  svc.StatusLog(),
		Now:        time.Now(),
	})
	failed := 0
	for _, f := range findings {
		if !f.OK {
			failed++
		}
	}
	if asJSON {
		json.NewEncoder(os.Stdout).Encode(findings)
	} else {
		for _, f := range findings {
			mark := "ok   "
			if !f.OK {
				mark = "TROU "
			}
			fmt.Printf("%s %-9s %s\n", mark, f.Check, f.Detail)
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}

func notice(svc service.Service, args []string) {
	fs := flag.NewFlagSet("notice", flag.ExitOnError)
	session := fs.String("session", "", "Claude Code session id")
	maxAge := fs.Duration("max-age", 2*time.Second, "display duration")
	fs.Parse(args)
	if strings.ContainsAny(*session, "/.") || *session == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(svc.SessionsDir(), *session+".json"))
	if err != nil {
		return
	}
	var n struct {
		Time int64  `json:"time"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &n) == nil && time.Since(time.UnixMilli(n.Time)) <= *maxAge {
		fmt.Print(n.Text)
	}
}
