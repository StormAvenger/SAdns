// Package auth implements password authentication and sessions for SAdns
// server mode (`sadns serve`), used when the UI is reachable from other
// machines (LAN, Docker). The desktop UI keeps its loopback-only, one-time
// token model and does not use this package.
//
// Passwords are never stored: only a PBKDF2-HMAC-SHA256 hash with a random
// salt. Sessions live in memory only, so a restart signs everyone out.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Parameters. 600,000 iterations follows current OWASP guidance for
// PBKDF2-HMAC-SHA256.
const (
	Iterations     = 600_000
	saltLen        = 16
	keyLen         = 32
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// Hash is the stored password verifier (secrets/auth.json).
type Hash struct {
	Version    int       `json:"version"`
	Algo       string    `json:"algo"`
	Iterations int       `json:"iterations"`
	Salt       string    `json:"salt"`
	Key        string    `json:"key"`
	Created    time.Time `json:"created"`
	Generated  bool      `json:"generated"` // true if SAdns generated the password
}

// CheckPassword enforces length limits for user-chosen passwords.
func CheckPassword(pw string) error {
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(pw) > MaxPasswordLen {
		return fmt.Errorf("password must be at most %d characters", MaxPasswordLen)
	}
	return nil
}

// NewHash derives a verifier for pw.
func NewHash(pw string, generated bool) (Hash, error) { return newHash(pw, generated, Iterations) }

func newHash(pw string, generated bool, iter int) (Hash, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return Hash{}, err
	}
	k, err := pbkdf2.Key(sha256.New, pw, salt, iter, keyLen)
	if err != nil {
		return Hash{}, err
	}
	return Hash{Version: 1, Algo: "pbkdf2-sha256", Iterations: iter, Salt: base64.StdEncoding.EncodeToString(salt),
		Key: base64.StdEncoding.EncodeToString(k), Created: time.Now().UTC(), Generated: generated}, nil
}

// Verify checks pw in constant time with respect to the stored key.
func (h Hash) Verify(pw string) bool {
	if h.Algo != "pbkdf2-sha256" || h.Iterations < 10_000 || len(pw) > MaxPasswordLen {
		return false
	}
	salt, err1 := base64.StdEncoding.DecodeString(h.Salt)
	want, err2 := base64.StdEncoding.DecodeString(h.Key)
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, h.Iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Marshal / Unmarshal for the secrets file.
func (h Hash) Marshal() ([]byte, error) { return json.MarshalIndent(h, "", "  ") }

// ParseHash reads a stored verifier.
func ParseHash(b []byte) (Hash, error) {
	var h Hash
	if err := json.Unmarshal(b, &h); err != nil {
		return Hash{}, err
	}
	if h.Algo != "pbkdf2-sha256" || h.Key == "" || h.Salt == "" {
		return Hash{}, errors.New("unsupported or incomplete password hash")
	}
	return h, nil
}

// GeneratePassword returns a random 128-bit password formatted for reading
// from a log: 6 groups of 5 characters from an unambiguous alphabet.
func GeneratePassword() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no i, l, o, 0, 1
	var b [30]byte
	_, _ = rand.Read(b[:])
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Errors returned by Login.
var (
	ErrBadPassword = errors.New("incorrect password")
	ErrLocked      = errors.New("too many failed attempts; try again later")
)

type session struct {
	csrf    string
	created time.Time
	seen    time.Time
}

type failRec struct {
	n           int
	first       time.Time
	lockedUntil time.Time
}

// Manager verifies passwords and tracks sessions.
type Manager struct {
	hash Hash

	IdleTTL     time.Duration // session expires after this much inactivity
	MaxTTL      time.Duration // and in any case after this long
	MaxSessions int
	MaxFails    int           // failures per client within FailWindow before lockout
	FailWindow  time.Duration
	Lockout     time.Duration
	Now         func() time.Time

	mu       sync.Mutex
	sessions map[string]*session
	fails    map[string]*failRec
	sem      chan struct{} // bounds concurrent PBKDF2 work (CPU-exhaustion defence)
}

// NewManager creates a manager for the given verifier.
func NewManager(h Hash) *Manager {
	return &Manager{hash: h, IdleTTL: 12 * time.Hour, MaxTTL: 7 * 24 * time.Hour, MaxSessions: 64,
		MaxFails: 5, FailWindow: 5 * time.Minute, Lockout: 5 * time.Minute, Now: time.Now,
		sessions: map[string]*session{}, fails: map[string]*failRec{}, sem: make(chan struct{}, 2)}
}

// Login checks pw for a client (keyed by remote IP) and creates a session.
func (m *Manager) Login(client, pw string) (sid, csrf string, err error) {
	now := m.Now()
	m.mu.Lock()
	f := m.fails[client]
	if f != nil && now.Before(f.lockedUntil) {
		m.mu.Unlock()
		return "", "", ErrLocked
	}
	m.mu.Unlock()

	m.sem <- struct{}{}
	ok := m.hash.Verify(pw)
	<-m.sem

	m.mu.Lock()
	defer m.mu.Unlock()
	if !ok {
		f = m.fails[client]
		if f == nil || now.Sub(f.first) > m.FailWindow {
			f = &failRec{first: now}
			m.fails[client] = f
		}
		f.n++
		if f.n >= m.MaxFails {
			f.lockedUntil = now.Add(m.Lockout)
			f.n, f.first = 0, now
		}
		if len(m.fails) > 10000 { // bound memory under a spray of source addresses
			m.fails = map[string]*failRec{}
		}
		return "", "", ErrBadPassword
	}
	delete(m.fails, client)
	m.gc(now)
	if len(m.sessions) >= m.MaxSessions {
		var oldest string
		var ot time.Time
		for id, s := range m.sessions {
			if oldest == "" || s.seen.Before(ot) {
				oldest, ot = id, s.seen
			}
		}
		delete(m.sessions, oldest)
	}
	sid, csrf = randHex(32), randHex(32)
	m.sessions[sid] = &session{csrf: csrf, created: now, seen: now}
	return sid, csrf, nil
}

func (m *Manager) gc(now time.Time) {
	for id, s := range m.sessions {
		if now.Sub(s.seen) > m.IdleTTL || now.Sub(s.created) > m.MaxTTL {
			delete(m.sessions, id)
		}
	}
}

// Session validates a session ID, refreshes its idle timer, and returns its
// CSRF token.
func (m *Manager) Session(sid string) (string, bool) {
	if len(sid) != 64 {
		return "", false
	}
	now := m.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sid]
	if !ok {
		return "", false
	}
	if now.Sub(s.seen) > m.IdleTTL || now.Sub(s.created) > m.MaxTTL {
		delete(m.sessions, sid)
		return "", false
	}
	s.seen = now
	return s.csrf, true
}

// CheckCSRF compares a request's CSRF header with the session's token.
func (m *Manager) CheckCSRF(sid, token string) bool {
	csrf, ok := m.Session(sid)
	return ok && token != "" && subtle.ConstantTimeCompare([]byte(csrf), []byte(token)) == 1
}

// Logout ends one session.
func (m *Manager) Logout(sid string) {
	m.mu.Lock()
	delete(m.sessions, sid)
	m.mu.Unlock()
}

// Count returns the number of live sessions.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gc(m.Now())
	return len(m.sessions)
}
