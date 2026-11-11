// Package mockdns is a tiny configurable DNS server used by SAdns's tests
// (and handy for demoing the UI offline). It imitates healthy, broken,
// filtering and hijacking resolvers.
package mockdns

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/StormAvenger/SAdns/internal/dnswire"
)

// Behavior selects how the server misbehaves.
type Behavior struct {
	Validating   bool   // DNSSEC-validating (SERVFAIL for dnssec-failed.org, AD for ietf.org)
	HijackNX     bool   // answer NXDOMAIN names with an address
	Filtering    bool   // sinkhole ad domains to 0.0.0.0
	NoTCP        bool   // do not listen on TCP
	DropLargeUDP bool   // silently drop UDP responses > 512 bytes
	NoEDNS       bool   // strip OPT records from responses
	Version      string // CHAOS version.bind
	Egress       string // IP returned by o-o.myaddr.l.google.com
	ASN          string // ASN returned for origin lookups
}

// Server is a running mock resolver.
type Server struct {
	Addr string
	B    Behavior
	pc   net.PacketConn
	ln   net.Listener
	wg   sync.WaitGroup
}

// Start launches a server on 127.0.0.1 with a random port (same port for UDP+TCP).
func Start(b Behavior) (*Server, error) {
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		s := &Server{B: b, pc: pc, Addr: pc.LocalAddr().String()}
		if !b.NoTCP {
			ln, err := net.Listen("tcp", s.Addr)
			if err != nil {
				pc.Close()
				continue // port clash on TCP; retry
			}
			s.ln = ln
			s.wg.Add(1)
			go s.serveTCP()
		}
		s.wg.Add(1)
		go s.serveUDP()
		return s, nil
	}
	return nil, net.ErrClosed
}

// Close stops the server.
func (s *Server) Close() {
	s.pc.Close()
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q, err := dnswire.Unpack(buf[:n])
		if err != nil || len(q.Question) == 0 {
			continue
		}
		resp := s.answer(q)
		limit := 512
		if q.EDNS != nil && q.EDNS.UDPSize > 512 {
			limit = int(q.EDNS.UDPSize)
		}
		b, _ := resp.Pack()
		if len(b) > limit {
			resp.Answer, resp.Authority, resp.Additional = nil, nil, nil
			resp.TC = true
			b, _ = resp.Pack()
		}
		if s.B.DropLargeUDP && len(b) > 512 {
			continue
		}
		_, _ = s.pc.WriteTo(b, addr)
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				var lb [2]byte
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				q, err := dnswire.Unpack(buf)
				if err != nil || len(q.Question) == 0 {
					return
				}
				b, _ := s.answer(q).Pack()
				out := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
				if _, err := c.Write(append(out, b...)); err != nil {
					return
				}
			}
		}(c)
	}
}

func a4(s string) []byte  { a := netip.MustParseAddr(s).As4(); return a[:] }
func a16(s string) []byte { a := netip.MustParseAddr(s).As16(); return a[:] }

func (s *Server) answer(q *dnswire.Msg) *dnswire.Msg {
	qq := q.Question[0]
	name := strings.ToLower(strings.TrimSuffix(qq.Name, "."))
	r := &dnswire.Msg{Header: dnswire.Header{ID: q.ID, QR: true, RD: q.RD, RA: true}, Question: q.Question}
	if q.EDNS != nil && !s.B.NoEDNS {
		r.EDNS = &dnswire.EDNS{UDPSize: 1232, DO: q.EDNS.DO}
		for _, o := range q.EDNS.Options {
			if o.Code == dnswire.OptNSID {
				r.EDNS.Options = append(r.EDNS.Options, dnswire.EDNSOption{Code: dnswire.OptNSID, Data: []byte("mock-1")})
			}
		}
	}
	rr := func(t uint16, data []byte) dnswire.RR {
		return dnswire.RR{Name: qq.Name, Type: t, Class: qq.Class, TTL: 300, Data: data}
	}
	nx := func() { r.Rcode = dnswire.RcodeNXDomain }

	if qq.Class == dnswire.ClassCHAOS {
		if name == "version.bind" && s.B.Version != "" {
			r.Answer = append(r.Answer, rr(dnswire.TypeTXT, dnswire.TXTData(s.B.Version)))
		} else {
			r.Rcode = dnswire.RcodeRefused
		}
		return r
	}
	switch {
	case name == "example.com" && qq.Type == dnswire.TypeA:
		r.Answer = append(r.Answer, rr(dnswire.TypeA, a4("93.184.215.14")))
	case name == "example.com" && qq.Type == dnswire.TypeAAAA:
		r.Answer = append(r.Answer, rr(dnswire.TypeAAAA, a16("2606:2800:21f:cb07:6820:80da:af6b:1c27")))
	case name == "" && qq.Type == dnswire.TypeDNSKEY:
		key := make([]byte, 4+260)
		binary.BigEndian.PutUint16(key, 257)
		key[2], key[3] = 3, 8
		for i := 0; i < 4; i++ {
			r.Answer = append(r.Answer, rr(dnswire.TypeDNSKEY, key))
		}
		if q.EDNS != nil && q.EDNS.DO {
			r.Answer = append(r.Answer, rr(dnswire.TypeRRSIG, make([]byte, 280)))
		}
	case name == "ietf.org":
		r.Answer = append(r.Answer, rr(dnswire.TypeA, a4("104.16.44.99")))
		r.AD = s.B.Validating && (q.AD || (q.EDNS != nil && q.EDNS.DO))
	case name == "dnssec-failed.org":
		if s.B.Validating {
			r.Rcode = dnswire.RcodeServFail
			if r.EDNS != nil {
				r.EDNS.Options = append(r.EDNS.Options, dnswire.EDNSOption{Code: dnswire.OptEDE, Data: append([]byte{0, 6}, "mock bogus"...)})
			}
		} else {
			r.Answer = append(r.Answer, rr(dnswire.TypeA, a4("96.99.227.255")))
		}
	case name == "pagead2.googlesyndication.com" || name == "ad.doubleclick.net":
		if s.B.Filtering {
			r.Answer = append(r.Answer, rr(dnswire.TypeA, a4("0.0.0.0")))
		} else {
			r.Answer = append(r.Answer, rr(dnswire.TypeA, a4("142.250.72.2")))
		}
	case name == "o-o.myaddr.l.google.com" && s.B.Egress != "":
		r.Answer = append(r.Answer, rr(dnswire.TypeTXT, dnswire.TXTData(s.B.Egress)))
	case strings.HasSuffix(name, ".origin.asn.cymru.com") || strings.HasSuffix(name, ".origin6.asn.cymru.com"):
		asn := s.B.ASN
		if asn == "" {
			asn = "64500"
		}
		r.Answer = append(r.Answer, rr(dnswire.TypeTXT, dnswire.TXTData(asn+" | 203.0.113.0/24 | US | arin | 2020-01-01")))
	case strings.HasPrefix(name, "as") && strings.HasSuffix(name, ".asn.cymru.com"):
		r.Answer = append(r.Answer, rr(dnswire.TypeTXT, dnswire.TXTData(strings.TrimPrefix(strings.TrimSuffix(name, ".asn.cymru.com"), "as")+" | US | arin | 2020-01-01 | EXAMPLE-NET, US")))
	default:
		if s.B.HijackNX && qq.Type == dnswire.TypeA {
			r.Answer = append(r.Answer, rr(dnswire.TypeA, a4("198.51.100.77")))
		} else {
			nx()
		}
	}
	return r
}
