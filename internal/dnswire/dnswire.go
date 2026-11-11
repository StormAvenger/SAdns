// Package dnswire is a small, dependency-free DNS message encoder/decoder
// (RFC 1035, RFC 6891 EDNS0, RFC 8914 Extended DNS Errors). It implements
// exactly what SAdns needs to build queries and inspect responses.
package dnswire

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Record types.
const (
	TypeA      uint16 = 1
	TypeNS     uint16 = 2
	TypeCNAME  uint16 = 5
	TypeSOA    uint16 = 6
	TypePTR    uint16 = 12
	TypeMX     uint16 = 15
	TypeTXT    uint16 = 16
	TypeAAAA   uint16 = 28
	TypeOPT    uint16 = 41
	TypeDS     uint16 = 43
	TypeRRSIG  uint16 = 46
	TypeNSEC   uint16 = 47
	TypeDNSKEY uint16 = 48
	TypeNSEC3  uint16 = 50
	TypeSVCB   uint16 = 64
	TypeHTTPS  uint16 = 65
)

// Classes.
const (
	ClassINET  uint16 = 1
	ClassCHAOS uint16 = 3
)

// Response codes (including extended RCODEs from EDNS).
const (
	RcodeSuccess  uint16 = 0
	RcodeFormErr  uint16 = 1
	RcodeServFail uint16 = 2
	RcodeNXDomain uint16 = 3
	RcodeNotImp   uint16 = 4
	RcodeRefused  uint16 = 5
	RcodeBadVers  uint16 = 16
)

// EDNS option codes.
const (
	OptNSID uint16 = 3
	OptEDE  uint16 = 15
)

var typeNames = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeOPT: "OPT", TypeDS: "DS",
	TypeRRSIG: "RRSIG", TypeNSEC: "NSEC", TypeDNSKEY: "DNSKEY", TypeNSEC3: "NSEC3",
	TypeSVCB: "SVCB", TypeHTTPS: "HTTPS",
}

var rcodeNames = map[uint16]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
	5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
	10: "NOTZONE", 16: "BADVERS",
}

// EDECodeNames maps RFC 8914 Extended DNS Error info-codes to names.
var EDECodeNames = map[uint16]string{
	0: "Other", 1: "Unsupported DNSKEY Algorithm", 2: "Unsupported DS Digest Type",
	3: "Stale Answer", 4: "Forged Answer", 5: "DNSSEC Indeterminate", 6: "DNSSEC Bogus",
	7: "Signature Expired", 8: "Signature Not Yet Valid", 9: "DNSKEY Missing",
	10: "RRSIGs Missing", 11: "No Zone Key Bit Set", 12: "NSEC Missing", 13: "Cached Error",
	14: "Not Ready", 15: "Blocked", 16: "Censored", 17: "Filtered", 18: "Prohibited",
	19: "Stale NXDOMAIN Answer", 20: "Not Authoritative", 21: "Not Supported",
	22: "No Reachable Authority", 23: "Network Error", 24: "Invalid Data",
	25: "Signature Expired before Valid", 26: "Too Early",
	27: "Unsupported NSEC3 Iterations Value", 28: "Unable to conform to policy",
	29: "Synthesized", 30: "Invalid Query Type",
}

// TypeString returns the mnemonic for a record type.
func TypeString(t uint16) string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// RcodeString returns the mnemonic for a response code.
func RcodeString(r uint16) string {
	if s, ok := rcodeNames[r]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(int(r))
}

var (
	ErrShort       = errors.New("dnswire: message too short")
	ErrPointer     = errors.New("dnswire: bad compression pointer")
	ErrLabel       = errors.New("dnswire: bad label")
	ErrNameTooLong = errors.New("dnswire: name too long")
)

// Header is the fixed DNS header (with the RCODE widened to hold EDNS extended bits).
type Header struct {
	ID     uint16
	QR     bool
	Opcode uint8
	AA     bool
	TC     bool
	RD     bool
	RA     bool
	AD     bool
	CD     bool
	Rcode  uint16
}

// Question is a single DNS question.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RR is a resource record. Data holds the raw RDATA; Text is a
// presentation-format rendering computed during Unpack.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte
	Text  string
}

// EDNSOption is a raw EDNS0 option.
type EDNSOption struct {
	Code uint16
	Data []byte
}

// EDNS holds the decoded OPT pseudo-record.
type EDNS struct {
	UDPSize  uint16
	ExtRcode uint8
	Version  uint8
	DO       bool
	Options  []EDNSOption
}

// EDE is a decoded Extended DNS Error.
type EDE struct {
	Code uint16
	Text string
}

func (e EDE) String() string {
	name := EDECodeNames[e.Code]
	if name == "" {
		name = "Unknown"
	}
	s := fmt.Sprintf("EDE %d (%s)", e.Code, name)
	if e.Text != "" {
		s += ": " + e.Text
	}
	return s
}

// Msg is a full DNS message.
type Msg struct {
	Header
	Question   []Question
	Answer     []RR
	Authority  []RR
	Additional []RR // excludes the OPT record, which is surfaced as EDNS
	EDNS       *EDNS
}

// QueryOpts controls how NewQuery builds a query.
type QueryOpts struct {
	Class   uint16 // default ClassINET
	NoRD    bool   // clear the Recursion Desired bit
	AD      bool   // set the AD bit (RFC 6840: ask for AD in response)
	CD      bool   // checking disabled
	EDNS    bool   // attach an OPT record
	UDPSize uint16 // advertised UDP payload size (default 1232)
	DO      bool   // DNSSEC OK
	NSID    bool   // request the name server identifier
}

// NewQuery builds a query with a random ID.
func NewQuery(name string, qtype uint16, o QueryOpts) *Msg {
	class := o.Class
	if class == 0 {
		class = ClassINET
	}
	m := &Msg{
		Header:   Header{ID: RandomID(), RD: !o.NoRD, AD: o.AD, CD: o.CD},
		Question: []Question{{Name: Fqdn(name), Type: qtype, Class: class}},
	}
	if o.EDNS || o.DO || o.NSID {
		size := o.UDPSize
		if size == 0 {
			size = 1232
		}
		e := &EDNS{UDPSize: size, DO: o.DO}
		if o.NSID {
			e.Options = append(e.Options, EDNSOption{Code: OptNSID})
		}
		m.EDNS = e
	}
	return m
}

// RandomID returns a cryptographically random 16-bit message ID.
func RandomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// RandomLabel returns a random lowercase alphanumeric label of length n.
func RandomLabel(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// Fqdn ensures a trailing dot.
func Fqdn(name string) string {
	if name == "" || name == "." {
		return "."
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// Pack serialises the message (no name compression).
func (m *Msg) Pack() ([]byte, error) {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], m.ID)
	var f uint16
	if m.QR {
		f |= 1 << 15
	}
	f |= uint16(m.Opcode&0xf) << 11
	if m.AA {
		f |= 1 << 10
	}
	if m.TC {
		f |= 1 << 9
	}
	if m.RD {
		f |= 1 << 8
	}
	if m.RA {
		f |= 1 << 7
	}
	if m.AD {
		f |= 1 << 5
	}
	if m.CD {
		f |= 1 << 4
	}
	f |= m.Rcode & 0xf
	binary.BigEndian.PutUint16(b[2:], f)
	ar := len(m.Additional)
	if m.EDNS != nil {
		ar++
	}
	binary.BigEndian.PutUint16(b[4:], uint16(len(m.Question)))
	binary.BigEndian.PutUint16(b[6:], uint16(len(m.Answer)))
	binary.BigEndian.PutUint16(b[8:], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(b[10:], uint16(ar))

	var err error
	for _, q := range m.Question {
		if b, err = appendName(b, q.Name); err != nil {
			return nil, err
		}
		b = binary.BigEndian.AppendUint16(b, q.Type)
		b = binary.BigEndian.AppendUint16(b, q.Class)
	}
	for _, sec := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for _, rr := range sec {
			if b, err = appendRR(b, rr); err != nil {
				return nil, err
			}
		}
	}
	if e := m.EDNS; e != nil {
		b = append(b, 0) // root name
		b = binary.BigEndian.AppendUint16(b, TypeOPT)
		b = binary.BigEndian.AppendUint16(b, e.UDPSize)
		ext := uint8((m.Rcode >> 4) & 0xff)
		if e.ExtRcode != 0 {
			ext = e.ExtRcode
		}
		ttl := uint32(ext)<<24 | uint32(e.Version)<<16
		if e.DO {
			ttl |= 1 << 15
		}
		b = binary.BigEndian.AppendUint32(b, ttl)
		var rd []byte
		for _, o := range e.Options {
			rd = binary.BigEndian.AppendUint16(rd, o.Code)
			rd = binary.BigEndian.AppendUint16(rd, uint16(len(o.Data)))
			rd = append(rd, o.Data...)
		}
		b = binary.BigEndian.AppendUint16(b, uint16(len(rd)))
		b = append(b, rd...)
	}
	return b, nil
}

func appendRR(b []byte, rr RR) ([]byte, error) {
	var err error
	if b, err = appendName(b, rr.Name); err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, rr.Type)
	b = binary.BigEndian.AppendUint16(b, rr.Class)
	b = binary.BigEndian.AppendUint32(b, rr.TTL)
	if len(rr.Data) > 0xffff {
		return nil, errors.New("dnswire: rdata too long")
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(rr.Data)))
	return append(b, rr.Data...), nil
}

func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(b, 0), nil
	}
	if len(name) > 253 {
		return nil, ErrNameTooLong
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, ErrLabel
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}

// EncodeName returns the uncompressed wire form of name (useful for building RDATA).
func EncodeName(name string) []byte {
	b, _ := appendName(nil, name)
	return b
}

// Unpack parses a wire-format DNS message.
func Unpack(b []byte) (*Msg, error) {
	if len(b) < 12 {
		return nil, ErrShort
	}
	m := &Msg{}
	m.ID = binary.BigEndian.Uint16(b[0:])
	f := binary.BigEndian.Uint16(b[2:])
	m.QR = f&(1<<15) != 0
	m.Opcode = uint8((f >> 11) & 0xf)
	m.AA = f&(1<<10) != 0
	m.TC = f&(1<<9) != 0
	m.RD = f&(1<<8) != 0
	m.RA = f&(1<<7) != 0
	m.AD = f&(1<<5) != 0
	m.CD = f&(1<<4) != 0
	m.Rcode = f & 0xf
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))

	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(b, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+4 > len(b) {
			return nil, ErrShort
		}
		m.Question = append(m.Question, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(b[off:]),
			Class: binary.BigEndian.Uint16(b[off+2:]),
		})
		off += 4
	}
	readSection := func(count int) ([]RR, error) {
		var out []RR
		for i := 0; i < count; i++ {
			rr, n, err := readRR(b, off)
			if err != nil {
				return out, err
			}
			off = n
			out = append(out, rr)
		}
		return out, nil
	}
	var err error
	if m.Answer, err = readSection(an); err != nil {
		return m, err
	}
	if m.Authority, err = readSection(ns); err != nil {
		return m, err
	}
	add, err := readSection(ar)
	for _, rr := range add {
		if rr.Type == TypeOPT {
			e := &EDNS{
				UDPSize:  rr.Class,
				ExtRcode: uint8(rr.TTL >> 24),
				Version:  uint8(rr.TTL >> 16),
				DO:       rr.TTL&(1<<15) != 0,
			}
			d := rr.Data
			for len(d) >= 4 {
				code := binary.BigEndian.Uint16(d)
				l := int(binary.BigEndian.Uint16(d[2:]))
				if 4+l > len(d) {
					break
				}
				e.Options = append(e.Options, EDNSOption{Code: code, Data: append([]byte(nil), d[4:4+l]...)})
				d = d[4+l:]
			}
			m.EDNS = e
			m.Rcode |= uint16(e.ExtRcode) << 4
			continue
		}
		m.Additional = append(m.Additional, rr)
	}
	return m, err
}

func readName(b []byte, off int) (string, int, error) {
	var labels []string
	ret := -1
	jumps := 0
	total := 0
	for {
		if off >= len(b) {
			return "", 0, ErrShort
		}
		c := int(b[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				off++
				if ret < 0 {
					ret = off
				}
				name := strings.Join(labels, ".") + "."
				return name, ret, nil
			}
			if off+1+c > len(b) {
				return "", 0, ErrShort
			}
			total += c + 1
			if total > 255 {
				return "", 0, ErrNameTooLong
			}
			labels = append(labels, escapeLabel(b[off+1:off+1+c]))
			off += 1 + c
		case 0xC0:
			if off+1 >= len(b) {
				return "", 0, ErrShort
			}
			if ret < 0 {
				ret = off + 2
			}
			jumps++
			if jumps > 64 {
				return "", 0, ErrPointer
			}
			ptr := int(binary.BigEndian.Uint16(b[off:]) & 0x3FFF)
			if ptr >= len(b) {
				return "", 0, ErrPointer
			}
			off = ptr
		default:
			return "", 0, ErrLabel
		}
	}
}

func escapeLabel(l []byte) string {
	var sb strings.Builder
	for _, c := range l {
		switch {
		case c == '.' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 0x21 || c > 0x7e:
			fmt.Fprintf(&sb, "\\%03d", c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func readRR(b []byte, off int) (RR, int, error) {
	name, off, err := readName(b, off)
	if err != nil {
		return RR{}, 0, err
	}
	if off+10 > len(b) {
		return RR{}, 0, ErrShort
	}
	rr := RR{
		Name:  name,
		Type:  binary.BigEndian.Uint16(b[off:]),
		Class: binary.BigEndian.Uint16(b[off+2:]),
		TTL:   binary.BigEndian.Uint32(b[off+4:]),
	}
	l := int(binary.BigEndian.Uint16(b[off+8:]))
	off += 10
	if off+l > len(b) {
		return RR{}, 0, ErrShort
	}
	rr.Data = append([]byte(nil), b[off:off+l]...)
	rr.Text = rdataText(b, off, l, rr.Type)
	return rr, off + l, nil
}

func rdataText(msg []byte, off, l int, t uint16) string {
	d := msg[off : off+l]
	switch t {
	case TypeA:
		if l == 4 {
			return netip.AddrFrom4([4]byte(d)).String()
		}
	case TypeAAAA:
		if l == 16 {
			return netip.AddrFrom16([16]byte(d)).String()
		}
	case TypeCNAME, TypeNS, TypePTR:
		if n, _, err := readName(msg, off); err == nil {
			return n
		}
	case TypeMX:
		if l >= 3 {
			if n, _, err := readName(msg, off+2); err == nil {
				return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(d), n)
			}
		}
	case TypeSOA:
		mname, o2, err := readName(msg, off)
		if err != nil {
			break
		}
		rname, o3, err := readName(msg, o2)
		if err != nil || o3+20 > off+l {
			break
		}
		serial := binary.BigEndian.Uint32(msg[o3:])
		return fmt.Sprintf("%s %s %d", mname, rname, serial)
	case TypeTXT:
		return strings.Join(ParseTXT(d), " ")
	case TypeRRSIG:
		if l >= 18 {
			return fmt.Sprintf("covers=%s alg=%d", TypeString(binary.BigEndian.Uint16(d)), d[2])
		}
	case TypeDNSKEY:
		if l >= 4 {
			return fmt.Sprintf("flags=%d proto=%d alg=%d keylen=%d", binary.BigEndian.Uint16(d), d[2], d[3], l-4)
		}
	case TypeDS:
		if l >= 4 {
			return fmt.Sprintf("keytag=%d alg=%d digest=%d", binary.BigEndian.Uint16(d), d[2], d[3])
		}
	}
	if l > 32 {
		return fmt.Sprintf("\\# %d %s…", l, hex.EncodeToString(d[:32]))
	}
	return fmt.Sprintf("\\# %d %s", l, hex.EncodeToString(d))
}

// ParseTXT splits TXT RDATA into its character-strings.
func ParseTXT(d []byte) []string {
	var out []string
	for len(d) > 0 {
		l := int(d[0])
		if 1+l > len(d) {
			break
		}
		out = append(out, string(d[1:1+l]))
		d = d[1+l:]
	}
	return out
}

// TXTData builds TXT RDATA from strings (each truncated to 255 bytes).
func TXTData(ss ...string) []byte {
	var b []byte
	for _, s := range ss {
		if len(s) > 255 {
			s = s[:255]
		}
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return b
}

// Addrs returns all A/AAAA addresses in the answer section.
func (m *Msg) Addrs() []netip.Addr {
	var out []netip.Addr
	for _, rr := range m.Answer {
		switch {
		case rr.Type == TypeA && len(rr.Data) == 4:
			out = append(out, netip.AddrFrom4([4]byte(rr.Data)))
		case rr.Type == TypeAAAA && len(rr.Data) == 16:
			out = append(out, netip.AddrFrom16([16]byte(rr.Data)))
		}
	}
	return out
}

// TXT returns all TXT strings in the answer section (each RR joined).
func (m *Msg) TXT() []string {
	var out []string
	for _, rr := range m.Answer {
		if rr.Type == TypeTXT {
			out = append(out, strings.Join(ParseTXT(rr.Data), ""))
		}
	}
	return out
}

// AnswerStrings renders answer records as "TYPE value".
func (m *Msg) AnswerStrings() []string {
	var out []string
	for _, rr := range m.Answer {
		out = append(out, TypeString(rr.Type)+" "+rr.Text)
	}
	return out
}

// EDEs returns any Extended DNS Errors attached to the response.
func (m *Msg) EDEs() []EDE {
	if m.EDNS == nil {
		return nil
	}
	var out []EDE
	for _, o := range m.EDNS.Options {
		if o.Code == OptEDE && len(o.Data) >= 2 {
			out = append(out, EDE{Code: binary.BigEndian.Uint16(o.Data), Text: strings.TrimRight(string(o.Data[2:]), "\x00")})
		}
	}
	return out
}

// NSID returns the name server identifier if present (printable, else hex).
func (m *Msg) NSID() string {
	if m.EDNS == nil {
		return ""
	}
	for _, o := range m.EDNS.Options {
		if o.Code == OptNSID && len(o.Data) > 0 {
			printable := true
			for _, c := range o.Data {
				if c < 0x20 || c > 0x7e {
					printable = false
					break
				}
			}
			if printable {
				return string(o.Data)
			}
			return hex.EncodeToString(o.Data)
		}
	}
	return ""
}

// FlagString renders header flags in dig style, e.g. "qr rd ra ad".
func (m *Msg) FlagString() string {
	var f []string
	add := func(on bool, s string) {
		if on {
			f = append(f, s)
		}
	}
	add(m.QR, "qr")
	add(m.AA, "aa")
	add(m.TC, "tc")
	add(m.RD, "rd")
	add(m.RA, "ra")
	add(m.AD, "ad")
	add(m.CD, "cd")
	return strings.Join(f, " ")
}

// ReverseName returns the in-addr.arpa / ip6.arpa name for an address, without
// the arpa suffix when suffix is non-empty (e.g. for origin.asn.cymru.com).
func ReverseName(a netip.Addr, suffix string) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		if suffix == "" {
			suffix = "in-addr.arpa."
		}
		return fmt.Sprintf("%d.%d.%d.%d.%s", b[3], b[2], b[1], b[0], suffix)
	}
	b := a.As16()
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0xf, b[i]>>4)
	}
	if suffix == "" {
		suffix = "ip6.arpa."
	}
	sb.WriteString(suffix)
	return sb.String()
}
