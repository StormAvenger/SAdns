package dnswire

import "testing"

// Benchmarks for docs/LANGUAGE-EVALUATION.md.
func BenchmarkPackQuery(b *testing.B) {
	q := NewQuery("www.example.com", TypeA, QueryOpts{EDNS: true, DO: true, NSID: true})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := q.Pack(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnpackQuery(b *testing.B) {
	wire, _ := NewQuery("www.example.com", TypeAAAA, QueryOpts{EDNS: true, DO: true}).Pack()
	b.ReportAllocs()
	b.SetBytes(int64(len(wire)))
	for i := 0; i < b.N; i++ {
		if _, err := Unpack(wire); err != nil {
			b.Fatal(err)
		}
	}
}
