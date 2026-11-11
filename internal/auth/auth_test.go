package auth

import (
	"strings"
	"testing"
	"time"
)

func fastHash(t *testing.T, pw string) Hash {
	t.Helper()
	h, err := newHash(pw, false, 20_000)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashRoundTrip(t *testing.T) {
	h, err := NewHash("correct horse battery", true)
	if err != nil {
		t.Fatal(err)
	}
	if h.Iterations != Iterations || !h.Generated {
		t.Fatalf("%+v", h)
	}
	b, _ := h.Marshal()
	if strings.Contains(string(b), "correct horse") {
		t.Fatal("plaintext in stored hash")
	}
	h2, err := ParseHash(b)
	if err != nil || !h2.Verify("correct horse battery") || h2.Verify("correct horse batterY") || h2.Verify("") {
		t.Fatal("verify")
	}
	a, _ := newHash("same password!!", false, 20_000)
	c, _ := newHash("same password!!", false, 20_000)
	if a.Salt == c.Salt || a.Key == c.Key {
		t.Error("salt not random")
	}
	if _, err := ParseHash([]byte(`{"algo":"md5","key":"x","salt":"y"}`)); err == nil {
		t.Error("unsupported algo accepted")
	}
	weak := a
	weak.Iterations = 1
	if weak.Verify("same password!!") {
		t.Error("weak iteration count accepted")
	}
}

func TestGeneratedPassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p := GeneratePassword()
		if CheckPassword(p) != nil || len(p) != 35 || strings.ContainsAny(p, "il01oO") {
			t.Fatalf("bad generated password %q", p)
		}
		if seen[p] {
			t.Fatal("duplicate")
		}
		seen[p] = true
	}
	if CheckPassword("short") == nil || CheckPassword(strings.Repeat("x", 300)) == nil {
		t.Error("length limits not enforced")
	}
}

func TestLoginLockoutAndSessions(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := NewManager(fastHash(t, "the right password"))
	m.Now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if _, _, err := m.Login("10.0.0.5", "wrong"); err != ErrBadPassword {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := m.Login("10.0.0.5", "the right password"); err != ErrLocked {
		t.Fatalf("expected lockout even with right password, got %v", err)
	}
	// Other clients are unaffected.
	sid, csrf, err := m.Login("10.0.0.6", "the right password")
	if err != nil || len(sid) != 64 || len(csrf) != 64 {
		t.Fatalf("login: %v", err)
	}
	now = now.Add(6 * time.Minute)
	if _, _, err := m.Login("10.0.0.5", "the right password"); err != nil {
		t.Fatalf("after lockout expiry: %v", err)
	}
	if !m.CheckCSRF(sid, csrf) || m.CheckCSRF(sid, "x"+csrf[1:]) || m.CheckCSRF(sid, "") || m.CheckCSRF("nope", csrf) {
		t.Fatal("csrf check")
	}
	// Idle expiry.
	now = now.Add(13 * time.Hour)
	if _, ok := m.Session(sid); ok {
		t.Fatal("idle session still valid")
	}
	// Activity keeps a session alive, but not past MaxTTL.
	sid2, _, _ := m.Login("10.0.0.7", "the right password")
	created := now
	for now.Add(11*time.Hour).Sub(created) < m.MaxTTL {
		now = now.Add(11 * time.Hour)
		if _, ok := m.Session(sid2); !ok {
			t.Fatalf("active session expired early after %v", now.Sub(created))
		}
	}
	now = now.Add(11 * time.Hour)
	if _, ok := m.Session(sid2); ok {
		t.Fatal("session outlived MaxTTL")
	}
	m.Logout(sid2)
}

func TestSessionCap(t *testing.T) {
	m := NewManager(fastHash(t, "the right password"))
	m.MaxSessions = 3
	first, _, _ := m.Login("a", "the right password")
	for i := 0; i < 3; i++ {
		time.Sleep(time.Millisecond)
		_, _, _ = m.Login("a", "the right password")
	}
	if m.Count() != 3 {
		t.Fatalf("count %d", m.Count())
	}
	if _, ok := m.Session(first); ok {
		t.Error("oldest session not evicted")
	}
}
