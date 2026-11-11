package auth

import (
	"os"
	"path/filepath"
	"testing"
)

type memStore map[string][]byte

func (m memStore) ReadSecret(n string) ([]byte, error) {
	if b, ok := m[n]; ok {
		return b, nil
	}
	return nil, os.ErrNotExist
}
func (m memStore) WriteSecret(n string, b []byte) error { m[n] = b; return nil }

func TestBootstrap(t *testing.T) {
	st := memStore{}
	h, pw, src, err := Bootstrap(st, "", false)
	if err != nil || src != SourceGenerated || pw == "" || !h.Verify(pw) {
		t.Fatalf("first start: %v %s", err, src)
	}
	if _, ok := st[HashFile]; !ok {
		t.Fatal("hash not stored")
	}
	if string(st[HashFile]) == pw || len(st[HashFile]) == 0 {
		t.Fatal("bad stored content")
	}
	// Second start: stored hash, nothing printed.
	h2, pw2, src2, err := Bootstrap(st, "", false)
	if err != nil || src2 != SourceStored || pw2 != "" || !h2.Verify(pw) {
		t.Fatalf("restart: %v %s", err, src2)
	}
	// Reset generates a different password.
	_, pw3, src3, _ := Bootstrap(st, "", true)
	if src3 != SourceGenerated || pw3 == pw {
		t.Fatal("reset")
	}
	// Environment wins and is not persisted.
	before := string(st[HashFile])
	h4, pw4, src4, err := Bootstrap(st, "my own long passphrase", false)
	if err != nil || src4 != SourceEnv || pw4 != "" || !h4.Verify("my own long passphrase") || string(st[HashFile]) != before {
		t.Fatalf("env: %v %s", err, src4)
	}
	if _, _, _, err := Bootstrap(st, "short", false); err == nil {
		t.Error("short env password accepted")
	}
	st[HashFile] = []byte("garbage")
	if _, _, _, err := Bootstrap(st, "", false); err == nil {
		t.Error("corrupt hash silently replaced")
	}
}

func TestPasswordFromEnv(t *testing.T) {
	f := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(f, []byte("from a docker secret\n"), 0o600)
	env := map[string]string{"SADNS_PASSWORD_FILE": f}
	p, err := PasswordFromEnv(func(k string) string { return env[k] })
	if err != nil || p != "from a docker secret" {
		t.Fatalf("%q %v", p, err)
	}
	env["SADNS_PASSWORD"] = "direct value wins"
	if p, _ := PasswordFromEnv(func(k string) string { return env[k] }); p != "direct value wins" {
		t.Fatal(p)
	}
	env = map[string]string{"SADNS_PASSWORD_FILE": "/nonexistent/x"}
	if _, err := PasswordFromEnv(func(k string) string { return env[k] }); err == nil {
		t.Error("missing file not reported")
	}
}
