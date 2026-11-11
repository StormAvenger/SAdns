package auth

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// SecretStore is where the password hash is persisted (store.Store).
type SecretStore interface {
	ReadSecret(name string) ([]byte, error)
	WriteSecret(name string, data []byte) error
}

// HashFile is the name of the stored verifier in the secrets directory.
const HashFile = "auth.json"

// Source describes where the active password came from.
type Source string

const (
	SourceEnv       Source = "environment"
	SourceStored    Source = "stored"
	SourceGenerated Source = "generated"
)

// Bootstrap decides the server password:
//
//   - envPassword (SADNS_PASSWORD or SADNS_PASSWORD_FILE) wins and is kept in
//     memory only — nothing is written;
//   - otherwise the stored hash is used;
//   - otherwise (or when reset is set) a random password is generated, only
//     its hash is stored, and the plaintext is returned once so the caller can
//     show it to the operator. There is never a default or shared password.
func Bootstrap(st SecretStore, envPassword string, reset bool) (h Hash, generated string, src Source, err error) {
	if envPassword != "" {
		if err := CheckPassword(envPassword); err != nil {
			return Hash{}, "", "", fmt.Errorf("SADNS_PASSWORD: %w", err)
		}
		h, err := NewHash(envPassword, false)
		return h, "", SourceEnv, err
	}
	if !reset {
		b, err := st.ReadSecret(HashFile)
		if err == nil {
			h, perr := ParseHash(b)
			if perr == nil {
				return h, "", SourceStored, nil
			}
			return Hash{}, "", "", fmt.Errorf("stored password hash is unreadable (%v); start with --reset-password to generate a new one", perr)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return Hash{}, "", "", err
		}
	}
	pw := GeneratePassword()
	h, err = NewHash(pw, true)
	if err != nil {
		return Hash{}, "", "", err
	}
	b, err := h.Marshal()
	if err != nil {
		return Hash{}, "", "", err
	}
	if err := st.WriteSecret(HashFile, b); err != nil {
		return Hash{}, "", "", fmt.Errorf("saving password hash: %w", err)
	}
	return h, pw, SourceGenerated, nil
}

// PasswordFromEnv reads SADNS_PASSWORD, or the file named by
// SADNS_PASSWORD_FILE (Docker/Compose secrets). Trailing newlines are removed.
func PasswordFromEnv(getenv func(string) string) (string, error) {
	if p := getenv("SADNS_PASSWORD"); p != "" {
		return p, nil
	}
	if f := getenv("SADNS_PASSWORD_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("SADNS_PASSWORD_FILE: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", nil
}
