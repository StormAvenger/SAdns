package dnswire

import (
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	q := NewQuery("Example.COM", TypeA, QueryOpts{EDNS: true, DO: true, NSID: true, UDPSize: 1400, AD: true})
	b, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	m, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != q.ID || !m.RD || !m.AD || m.QR {
		t.Fatalf("header mismatch: %+v", m.Header)
	}
	if m.Question[0].Name != "Example.COM." || m.Question[0].Type != TypeA {
		t.Fatalf("question: %+v", m.Question)
	}
	if m.EDNS == nil || !m.EDNS.DO || m.EDNS.UDPSize != 1400 || len(m.EDNS.Options) != 1 {
		t.Fatalf("edns: %+v", m.EDNS)
	}
}

// A real-world style response using name compression, an EDE and NSID.
func TestUnpackCompressed(t *testing.T) {
	b := []byte{
		0x12, 0x34, 0x81, 0xa0, 0, 1, 0, 2, 0, 0, 0, 1, // id, flags qr rd ra ad, counts
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6, 3, 'w', 'w', 'w', 0xc0, 12, // CNAME www.example.com
		0xc0, 41, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14, // A via pointer to www
		0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 14, // OPT 1232
		0, 15, 0, 4, 0, 6, 'x', 'y', // EDE 6 "xy"
		0, 3, 0, 2, 'n', '1', // NSID
	}
	m, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if !m.AD || !m.RA || m.Rcode != 0 {
		t.Fatalf("flags %s", m.FlagString())
	}
	if len(m.Answer) != 2 || m.Answer[0].Text != "www.example.com." || m.Answer[1].Name != "www.example.com." {
		t.Fatalf("answers %+v", m.Answer)
	}
	if a := m.Addrs(); len(a) != 1 || a[0] != netip.MustParseAddr("93.184.215.14") {
		t.Fatalf("addrs %v", a)
	}
	if e := m.EDEs(); len(e) != 1 || e[0].Code != 6 || e[0].Text != "xy" {
		t.Fatalf("ede %v", e)
	}
	if m.NSID() != "n1" || m.EDNS.UDPSize != 1232 {
		t.Fatalf("nsid %q size %d", m.NSID(), m.EDNS.UDPSize)
	}
}

func TestPointerLoop(t *testing.T) {
	b := []byte{0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12}
	if _, err := Unpack(b); err == nil {
		t.Fatal("expected error on pointer loop")
	}
}

func TestReverseName(t *testing.T) {
	if got := ReverseName(netip.MustParseAddr("1.2.3.4"), "origin.asn.cymru.com."); got != "4.3.2.1.origin.asn.cymru.com." {
		t.Fatal(got)
	}
	got := ReverseName(netip.MustParseAddr("2001:db8::1"), "")
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	if got != want {
		t.Fatalf("got %s", got)
	}
}

func FuzzUnpack(f *testing.F) {
	q, _ := NewQuery("example.com", TypeA, QueryOpts{EDNS: true}).Pack()
	f.Add(q)
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Unpack(b) })
}
