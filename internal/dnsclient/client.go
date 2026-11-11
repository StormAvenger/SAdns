// Package dnsclient sends DNS queries over UDP, TCP, DNS-over-TLS (RFC 7858)
// and DNS-over-HTTPS (RFC 8484) to an explicit server address. It never uses
// the operating system resolver or any HTTP proxy, so every measurement
// reflects the network path to that exact server.
package dnsclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/StormAvenger/SAdns/internal/dnswire"
)

// Proto is a DNS transport.
type Proto string

const (
	UDP Proto = "udp"
	TCP Proto = "tcp"
	DoT Proto = "dot"
	DoH Proto = "doh"
)

// Endpoint identifies a server and transport.
type Endpoint struct {
	Addr    netip.AddrPort
	Proto   Proto
	TLSName string // SNI + certificate name for DoT/DoH
	DoHPath string // e.g. "/dns-query"
}

func (e Endpoint) String() string {
	switch e.Proto {
	case DoH:
		return fmt.Sprintf("https://%s%s (via %s)", e.TLSName, e.DoHPath, e.Addr)
	case DoT:
		return fmt.Sprintf("tls://%s (%s)", e.Addr, e.TLSName)
	}
	return fmt.Sprintf("%s://%s", e.Proto, e.Addr)
}

// TLSInfo summarises an encrypted session.
type TLSInfo struct {
	Version     string `json:"version"`
	Cipher      string `json:"cipher"`
	ALPN        string `json:"alpn,omitempty"`
	HTTPProto   string `json:"http_proto,omitempty"`
	PeerSubject string `json:"peer_subject"`
	PeerIssuer  string `json:"peer_issuer"`
	NotAfter    string `json:"not_after"`
}

// Response is the outcome of one exchange.
type Response struct {
	Msg       *dnswire.Msg
	RTT       time.Duration // total time incl. connection setup
	Connect   time.Duration // TCP/TLS setup portion (0 for UDP)
	Size      int           // response size in bytes
	Err       error
	ErrClass  string // timeout, refused, unreachable, tls, http, malformed, other
	TLS       *TLSInfo
	LocalAddr string
}

// OK reports whether a parseable response was received.
func (r Response) OK() bool { return r.Err == nil && r.Msg != nil }

// Exchange sends q to ep and waits up to timeout for a matching response.
func Exchange(ctx context.Context, ep Endpoint, q *dnswire.Msg, timeout time.Duration) Response {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var r Response
	switch ep.Proto {
	case UDP, "":
		r = exchangeUDP(ctx, ep, q)
	case TCP:
		r = exchangeStream(ctx, ep, q, false)
	case DoT:
		r = exchangeStream(ctx, ep, q, true)
	case DoH:
		r = exchangeDoH(ctx, ep, q)
	default:
		r.Err = fmt.Errorf("unknown transport %q", ep.Proto)
	}
	if r.Err != nil && r.ErrClass == "" {
		r.ErrClass = Classify(r.Err)
	}
	return r
}

func exchangeUDP(ctx context.Context, ep Endpoint, q *dnswire.Msg) Response {
	var r Response
	pkt, err := q.Pack()
	if err != nil {
		r.Err = err
		return r
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", ep.Addr.String())
	if err != nil {
		r.Err = err
		return r
	}
	defer conn.Close()
	r.LocalAddr = conn.LocalAddr().String()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		r.Err = err
		return r
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			r.Err = err
			r.RTT = time.Since(start)
			return r
		}
		m, perr := dnswire.Unpack(buf[:n])
		if m == nil || m.ID != q.ID || !m.QR {
			continue // stray or spoofed packet; keep waiting
		}
		if !sameQuestion(q, m) {
			continue
		}
		r.RTT = time.Since(start)
		r.Size = n
		r.Msg = m
		if perr != nil && !m.TC {
			r.Err = fmt.Errorf("malformed response: %w", perr)
			r.ErrClass = "malformed"
		}
		return r
	}
}

func sameQuestion(q, m *dnswire.Msg) bool {
	if len(m.Question) == 0 {
		return true // some servers omit the question on errors
	}
	if len(q.Question) == 0 {
		return true
	}
	a, b := q.Question[0], m.Question[0]
	return strings.EqualFold(a.Name, b.Name) && a.Type == b.Type && a.Class == b.Class
}

func exchangeStream(ctx context.Context, ep Endpoint, q *dnswire.Msg, useTLS bool) Response {
	var r Response
	pkt, err := q.Pack()
	if err != nil {
		r.Err = err
		return r
	}
	start := time.Now()
	var conn net.Conn
	nd := &net.Dialer{}
	if useTLS {
		td := &tls.Dialer{NetDialer: nd, Config: &tls.Config{ServerName: ep.TLSName, MinVersion: tls.VersionTLS12}}
		conn, err = td.DialContext(ctx, "tcp", ep.Addr.String())
		if err == nil {
			r.TLS = tlsInfo(conn.(*tls.Conn).ConnectionState())
		}
	} else {
		conn, err = nd.DialContext(ctx, "tcp", ep.Addr.String())
	}
	if err != nil {
		r.Err = err
		r.RTT = time.Since(start)
		if useTLS && isTLSError(err) {
			r.ErrClass = "tls"
		}
		return r
	}
	defer conn.Close()
	r.LocalAddr = conn.LocalAddr().String()
	r.Connect = time.Since(start)
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	frame := make([]byte, 2, 2+len(pkt))
	binary.BigEndian.PutUint16(frame, uint16(len(pkt)))
	frame = append(frame, pkt...)
	if _, err := conn.Write(frame); err != nil {
		r.Err = err
		return r
	}
	for {
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			r.Err = err
			r.RTT = time.Since(start)
			return r
		}
		buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			r.Err = err
			r.RTT = time.Since(start)
			return r
		}
		m, perr := dnswire.Unpack(buf)
		if m == nil || m.ID != q.ID {
			continue
		}
		r.RTT = time.Since(start)
		r.Size = len(buf)
		r.Msg = m
		if perr != nil {
			r.Err = fmt.Errorf("malformed response: %w", perr)
			r.ErrClass = "malformed"
		}
		return r
	}
}

var (
	dohMu      sync.Mutex
	dohClients = map[string]*http.Client{}
)

func dohClient(ep Endpoint) *http.Client {
	key := ep.Addr.String() + "|" + ep.TLSName
	dohMu.Lock()
	defer dohMu.Unlock()
	if c, ok := dohClients[key]; ok {
		return c
	}
	nd := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // always go direct: we are testing the network path
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return nd.DialContext(ctx, "tcp", ep.Addr.String())
		},
		TLSClientConfig:     &tls.Config{ServerName: ep.TLSName, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
	}
	c := &http.Client{Transport: tr}
	dohClients[key] = c
	return c
}

func exchangeDoH(ctx context.Context, ep Endpoint, q *dnswire.Msg) Response {
	var r Response
	q.ID = 0 // RFC 8484 §4.1: use ID 0 for cache friendliness
	pkt, err := q.Pack()
	if err != nil {
		r.Err = err
		return r
	}
	path := ep.DoHPath
	if path == "" {
		path = "/dns-query"
	}
	url := "https://" + ep.TLSName + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(pkt))
	if err != nil {
		r.Err = err
		return r
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "SAdns")
	start := time.Now()
	resp, err := dohClient(ep).Do(req)
	if err != nil {
		r.Err = err
		r.RTT = time.Since(start)
		if isTLSError(err) {
			r.ErrClass = "tls"
		}
		return r
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	r.RTT = time.Since(start)
	if resp.TLS != nil {
		r.TLS = tlsInfo(*resp.TLS)
		r.TLS.HTTPProto = resp.Proto
	}
	if err != nil {
		r.Err = err
		return r
	}
	if resp.StatusCode != http.StatusOK {
		r.Err = fmt.Errorf("HTTP %d", resp.StatusCode)
		r.ErrClass = "http"
		return r
	}
	m, perr := dnswire.Unpack(body)
	if m == nil {
		r.Err = fmt.Errorf("malformed DoH body: %w", perr)
		r.ErrClass = "malformed"
		return r
	}
	r.Msg = m
	r.Size = len(body)
	return r
}

func tlsInfo(cs tls.ConnectionState) *TLSInfo {
	ti := &TLSInfo{
		Version: tls.VersionName(cs.Version),
		Cipher:  tls.CipherSuiteName(cs.CipherSuite),
		ALPN:    cs.NegotiatedProtocol,
	}
	if len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		ti.PeerSubject = c.Subject.CommonName
		ti.PeerIssuer = c.Issuer.CommonName
		if c.Issuer.Organization != nil && len(c.Issuer.Organization) > 0 {
			ti.PeerIssuer += " (" + c.Issuer.Organization[0] + ")"
		}
		ti.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
	return ti
}

func isTLSError(err error) bool {
	var ue x509.UnknownAuthorityError
	var he x509.HostnameError
	var ce x509.CertificateInvalidError
	var re tls.RecordHeaderError
	var ae tls.AlertError
	var ve *tls.CertificateVerificationError
	return errors.As(err, &ue) || errors.As(err, &he) || errors.As(err, &ce) ||
		errors.As(err, &re) || errors.As(err, &ae) || errors.As(err, &ve) ||
		strings.Contains(err.Error(), "tls:")
}

// Classify buckets a network error into a short, stable category.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	if isTLSError(err) {
		return "tls"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "timeout"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "unreachable") || strings.Contains(s, "no route"):
		return "unreachable"
	case strings.Contains(s, "address family not supported") || strings.Contains(s, "cannot assign requested address"):
		return "no-ipv6"
	case strings.Contains(s, "reset"):
		return "reset"
	case strings.Contains(s, "timeout") || strings.Contains(s, "timed out"):
		return "timeout"
	}
	return "other"
}
