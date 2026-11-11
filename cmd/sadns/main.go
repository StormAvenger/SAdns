// Command SAdns is a full-scope DNS and network diagnostic tool.
//
//	SAdns              launch the browser UI (or run in the terminal if no desktop is available)
//	sadns ui           launch the browser UI (loopback only, one-time token)
//	sadns run          run in the terminal and write report files
//	sadns serve        long-running service for Docker/LAN: password-protected UI, Auto Run, history
//	sadns healthcheck  exit 0 if a local `sadns serve` answers /healthz (container HEALTHCHECK)
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/analyze"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/probe"
	"github.com/StormAvenger/SAdns/internal/report"
	"github.com/StormAvenger/SAdns/internal/service"
	"github.com/StormAvenger/SAdns/internal/store"
	"github.com/StormAvenger/SAdns/internal/vantage"
	"github.com/StormAvenger/SAdns/internal/web"
)

// Set by -ldflags at release time.
var (
	version = "dev"
	commit  = "none"
	built   = "unknown"
)

const repo = "https://github.com/StormAvenger/SAdns"

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func realMain(args []string) int {
	mode := "auto"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	switch mode {
	case "auto", "ui", "run", "serve":
	case "healthcheck":
		return healthcheck(args)
	case "version":
		fmt.Printf("SAdns %s (commit %s, built %s, %s/%s)\n", version, commit, built, runtime.GOOS, runtime.GOARCH)
		return 0
	case "help":
		args = []string{"-h"}
		mode = "auto"
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (use: ui, run, serve, healthcheck, version, help)\n", mode)
		return 2
	}

	def := probe.DefaultConfig()
	fs := flag.NewFlagSet("SAdns", flag.ContinueOnError)
	var (
		quick      = fs.Bool("quick", false, "quick scan: primary address per provider, 3 samples, no traceroute")
		samples    = fs.Int("samples", def.Samples, "latency samples per resolver")
		timeout    = fs.Duration("timeout", def.Timeout, "per-query timeout")
		noTrace    = fs.Bool("no-traceroute", false, "skip traceroutes")
		lowData    = fs.Bool("low-data", false, "Low Data Mode: 1 website sample per address family, 512 KiB per response, 10 MiB HTTP budget per scan (all DNS/ping/routing tests still run)")
		noEnc      = fs.Bool("no-encrypted", false, "skip DNS-over-TLS / DNS-over-HTTPS tests")
		only4      = fs.Bool("4", false, "IPv4 only")
		only6      = fs.Bool("6", false, "IPv6 only")
		outDir     = fs.String("out", ".", "directory for report files (run mode)")
		privacy    = fs.String("privacy", "technical", "report privacy: full (nothing hidden), technical (hide public IPs, IPv6 prefix, hostname, MACs), public (also LAN IPs and internal domains)")
		redact     = fs.Bool("redact", false, "shortcut for --privacy public")
		stdoutFmt  = fs.String("stdout", "", "print the report to stdout instead of writing files: md or json (run mode)")
		listen     = fs.String("listen", "", "listen address: ui default 127.0.0.1:0 (loopback only); serve default $SADNS_LISTEN or :8053")
		dataDir    = fs.String("data-dir", "", "history/settings directory (default $SADNS_DATA_DIR or the per-user config dir)")
		save       = fs.Bool("save", false, "run mode: also store the scan in the history (data dir), e.g. for a Docker one-shot")
		resetPW    = fs.Bool("reset-password", false, "serve: generate a new random password (prints it once)")
		noAuth     = fs.Bool("no-auth", false, "serve: disable the password — only allowed on a loopback --listen address")
		allowHosts = fs.String("allowed-hosts", os.Getenv("SADNS_ALLOWED_HOSTS"), "serve: extra Host names accepted (comma-separated, '*' for any); IP addresses and localhost are always accepted")
		secureCk   = fs.Bool("secure-cookies", envBool("SADNS_SECURE_COOKIES"), "serve: mark session cookies Secure (set when an HTTPS reverse proxy fronts SAdns)")
		noBrowser  = fs.Bool("no-browser", false, "UI mode: print the URL instead of opening a browser")
		concurrent = fs.Int("concurrency", def.Concurrency, "resolvers tested in parallel")
		providers  listFlag
		extra      listFlag
		urls       listFlag
	)
	fs.Var(&urls, "url", "website or resource to time in addition to the baseline sites (e.g. a slow image URL); repeatable, max 5")
	fs.Var(&providers, "providers", "public providers to test, comma-separated ("+strings.Join(probe.ProviderKeys(), ",")+"); default all; 'none' to skip")
	fs.Var(&extra, "resolver", "extra resolver to test (ip or ip:port); repeatable or comma-separated")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "SAdns %s — full-scope DNS & network diagnostics\n\n", version)
		fmt.Fprintf(fs.Output(), "Usage:\n  sadns [ui|run|serve] [flags]\n\n  (no command)  open the browser UI; falls back to 'run' when no desktop is available\n  ui            open the browser UI (this computer only)\n  run           run in the terminal and write report .md/.json files\n  serve         long-running, password-protected service for Docker / LAN access (see docs/DOCKER.md)\n  healthcheck   probe a local 'serve' instance (exit 0 = healthy)\n  version       print version\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	cfg := def
	cfg.Quick = *quick
	cfg.Samples = *samples
	if *quick && !flagSet(fs, "samples") {
		cfg.Samples = 3
	}
	cfg.Timeout = *timeout
	cfg.Traceroute = !*noTrace && !*quick
	if flagSet(fs, "no-traceroute") {
		cfg.Traceroute = !*noTrace
	}
	cfg.Encrypted = !*noEnc
	cfg.LowData = *lowData
	cfg.Concurrency = *concurrent
	cfg.Extra = extra
	for i, u := range urls {
		n, err := probe.NormalizeURL(u)
		if err != nil || i >= probe.MaxCustomURLs {
			fmt.Fprintf(os.Stderr, "--url %q: %v (max %d http(s) URLs)\n", u, err, probe.MaxCustomURLs)
			return 2
		}
		cfg.URLs = append(cfg.URLs, n)
	}
	if *only4 || *only6 {
		cfg.IPv4, cfg.IPv6 = *only4, *only6
	}
	if len(providers) == 1 && providers[0] == "none" {
		cfg.NoProviders = true
	} else {
		for _, p := range providers {
			if probe.ProviderByKey(p) == nil {
				fmt.Fprintf(os.Stderr, "unknown provider %q (known: %s)\n", p, strings.Join(probe.ProviderKeys(), ", "))
				return 2
			}
		}
		cfg.Providers = providers
	}

	tool := model.ToolInfo{Name: "SAdns", Version: version, Commit: commit, Built: built, Repo: repo}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if mode == "auto" {
		if hasDesktop() {
			mode = "ui"
		} else {
			mode = "run"
			fmt.Fprintln(os.Stderr, "No desktop session detected — running in terminal mode (use 'sadns ui' to force the browser UI).")
		}
	}

	logf := func(f string, a ...any) { fmt.Printf(f+"\n", a...) }
	if mode == "ui" || mode == "serve" {
		if mode == "ui" {
			fmt.Printf("SAdns %s — DNS & network diagnostics\n\n", version)
		} else {
			logf("SAdns %s (%s/%s) starting in server mode", version, runtime.GOOS, runtime.GOARCH)
		}
		st, err := openStore(*dataDir, mode == "serve", logf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			pauseIfDoubleClicked()
			return 1
		}
		vant := vantage.Detect(vantage.System(), nil)
		svc := service.New(service.Options{Store: st, Defaults: cfg, Tool: tool, Vantage: applyVantage, Logf: logf})
		opt := web.Options{Service: svc, Tool: tool, Vantage: vant, Logf: logf}
		if mode == "ui" {
			opt.Mode, opt.Listen, opt.OpenBrowser = web.Desktop, *listen, !*noBrowser
		} else {
			opt.Mode, opt.Listen = web.Server, *listen
			if opt.Listen == "" {
				opt.Listen = envOr("SADNS_LISTEN", ":8053")
			}
			opt.SecureCookies = *secureCk
			opt.NoAuth = *noAuth || strings.EqualFold(os.Getenv("SADNS_AUTH"), "none")
			for _, h := range strings.Split(*allowHosts, ",") {
				if h = strings.TrimSpace(h); h != "" {
					opt.AllowedHosts = append(opt.AllowedHosts, h)
				}
			}
			if used, err := applySettingsEnv(st); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 2
			} else if len(used) > 0 {
				logf("Settings from environment: %s", strings.Join(used, ", "))
			}
			if !opt.NoAuth {
				mgr, err := setupAuth(st, *resetPW, logf)
				if err != nil {
					fmt.Fprintln(os.Stderr, "error:", err)
					return 1
				}
				opt.Auth = mgr
			} else {
				logf("WARNING: authentication is disabled (--no-auth). Only loopback clients can connect.")
			}
			if vant.InContainer {
				logf("Vantage: %s (%s) — %s", vant.Mode, vant.Detection, vant.Note)
			}
		}
		go svc.Run(ctx)
		err = web.Serve(ctx, opt)
		svc.Shutdown(10 * time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			pauseIfDoubleClicked()
			return 1
		}
		return 0
	}

	level := *privacy
	if *redact {
		level = "public"
	}
	var st *store.Store
	if *save {
		var err error
		if st, err = openStore(*dataDir, true, func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	return runCLI(ctx, cfg, tool, *outDir, level, *stdoutFmt, st)
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func runCLI(ctx context.Context, cfg probe.Config, tool model.ToolInfo, outDir string, privacy string, stdoutFmt string, st *store.Store) int {
	quiet := stdoutFmt != ""
	logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
	if !quiet {
		logf("SAdns %s — full-scope DNS & network diagnostics", tool.Version)
	}
	eng := probe.New(cfg, func(ev probe.Event) {
		switch ev.Type {
		case "phase":
			logf("[%3.0f%%] %s", ev.Progress*100, ev.Message)
		case "log":
			logf("       %s", ev.Message)
		case "resolver":
			if ev.Resolver != nil {
				r := ev.Resolver
				st := "unreachable"
				if r.Reachable {
					st = fmt.Sprintf("ok  median %.1f ms  dnssec=%s", r.Latency.MedianMS, r.DNSSEC)
				} else if len(r.Tests) > 0 && r.Tests[0].Status == model.Skip {
					st = "skipped"
				}
				logf("       %-38s %-28s %s", r.Label, r.Addr, st)
			}
		}
	})
	rep := eng.Run(ctx)
	rep.Tool = tool
	applyVantage(rep)
	analyze.Run(rep)
	if st != nil {
		status := ""
		if rep.Cancelled {
			status = store.StatusCancelled
		}
		if e, err := st.History.Save(rep, store.SaveMeta{Trigger: store.TriggerCLI, Status: status}); err != nil {
			logf("Could not save to history: %v", err)
		} else if !quiet {
			logf("Saved to history as %s (%s)", e.ID, st.Dir)
		}
	}

	switch stdoutFmt {
	case "md", "markdown":
		os.Stdout.Write(web.Render(rep, privacy, "md"))
		return 0
	case "json":
		os.Stdout.Write(web.Render(rep, privacy, "json"))
		return 0
	case "":
	default:
		logf("unknown --stdout format %q (md or json)", stdoutFmt)
		return 2
	}

	s := rep.Summary
	logf("")
	logf("Result: %s — %s", strings.ToUpper(s.Verdict), s.Headline)
	logf("        %d fail · %d warn · %d info · %d pass   (%.1f s)", s.Fail, s.Warn, s.Info, s.Pass, rep.DurationSec)
	for _, f := range rep.Findings {
		if f.Severity == model.Fail || f.Severity == model.Warn {
			logf("  [%s] %s", strings.ToUpper(f.Severity), f.Title)
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		logf("cannot create %s: %v", outDir, err)
		return 1
	}
	base := filepath.Join(outDir, web.FileBase(rep)+"-"+report.ParsePrivacy(privacy))
	for _, ext := range []string{"md", "json"} {
		p := base + "." + ext
		if err := os.WriteFile(p, web.Render(rep, privacy, ext), 0o644); err != nil {
			logf("write %s: %v", p, err)
			return 1
		}
		abs, _ := filepath.Abs(p)
		logf("Wrote %s", abs)
	}
	logf("\nPaste the .md file into your AI assistant for a diagnosis (privacy level: %s; use --privacy public before posting it publicly).", report.ParsePrivacy(privacy))
	pauseIfDoubleClicked()
	return 0
}

// hasDesktop guesses whether a browser can be opened.
func hasDesktop() bool {
	switch runtime.GOOS {
	case "windows", "darwin":
		return true
	}
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

// pauseIfDoubleClicked keeps the console open on Windows when launched from Explorer.
func pauseIfDoubleClicked() {
	if runtime.GOOS != "windows" || len(os.Args) > 1 {
		return
	}
	fmt.Fprint(os.Stderr, "\nPress Enter to close…")
	_ = time.AfterFunc(10*time.Minute, func() { os.Exit(0) })
	bufio.NewReader(os.Stdin).ReadString('\n')
}
