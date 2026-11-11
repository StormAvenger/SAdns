package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/auth"
	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/store"
	"github.com/StormAvenger/SAdns/internal/vantage"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string) bool {
	switch strings.ToLower(os.Getenv(k)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// applyVantage records where a report was measured from.
func applyVantage(rep *model.Report) {
	var gws []string
	if rep.System != nil {
		for _, g := range rep.System.Gateways {
			gws = append(gws, g.Gateway)
		}
	}
	rep.Vantage = vantage.Detect(vantage.System(), gws)
}

// openStore opens the data directory. The desktop UI falls back to a
// temporary directory (history then lasts only for this session) rather than
// refusing to start; server mode and `run --save` require persistence.
func openStore(dir string, required bool, logf func(string, ...any)) (*store.Store, error) {
	if dir == "" {
		d, err := store.DefaultDir()
		if err != nil && required {
			return nil, fmt.Errorf("no data directory: %w (set --data-dir or SADNS_DATA_DIR)", err)
		}
		dir = d
	}
	if dir != "" {
		st, err := store.Open(dir)
		if err == nil {
			if st.LoadWarning != nil {
				logf("Warning: %v", st.LoadWarning)
			}
			return st, nil
		}
		if required {
			return nil, fmt.Errorf("data directory %s: %w", dir, err)
		}
		logf("Warning: history unavailable in %s (%v); using a temporary directory for this session.", dir, err)
	}
	tmp, err := os.MkdirTemp("", "sadns-session-")
	if err != nil {
		return nil, err
	}
	return store.Open(tmp)
}

func applySettingsEnv(st *store.Store) ([]string, error) {
	set := st.Settings()
	used, err := store.ApplyEnv(&set, os.Getenv)
	if err != nil || len(used) == 0 {
		return used, err
	}
	return used, st.SaveSettings(set)
}

// setupAuth prepares the password manager. A generated password is printed
// exactly once; only its hash is kept.
func setupAuth(st *store.Store, reset bool, logf func(string, ...any)) (*auth.Manager, error) {
	envPW, err := auth.PasswordFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	h, generated, src, err := auth.Bootstrap(st, envPW, reset)
	if err != nil {
		return nil, err
	}
	switch src {
	case auth.SourceGenerated:
		logf("")
		logf("================================================================")
		logf("  SAdns generated a password for the web UI (shown only once):")
		logf("")
		logf("      %s", generated)
		logf("")
		logf("  Only a hash is stored. To choose your own, set SADNS_PASSWORD or")
		logf("  SADNS_PASSWORD_FILE; to generate a new one, restart with")
		logf("  --reset-password.")
		logf("================================================================")
		logf("")
	case auth.SourceEnv:
		logf("Using the password from SADNS_PASSWORD/SADNS_PASSWORD_FILE.")
	case auth.SourceStored:
		logf("Using the stored password hash (set SADNS_PASSWORD or use --reset-password to change it).")
	}
	return auth.NewManager(h), nil
}

// healthcheck probes a local server. Used as the container HEALTHCHECK so the
// image needs no curl/wget.
func healthcheck(args []string) int {
	addr := envOr("SADNS_LISTEN", ":8053")
	if len(args) > 0 {
		addr = args[0]
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
