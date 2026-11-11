package store

import (
	"testing"
	"time"
)

func BenchmarkSaveReport(b *testing.B) {
	s, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	_ = s.History.SetRetain(MaxRetain)
	r := rep(time.Now(), "healthy")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := s.History.Save(r, SaveMeta{Trigger: TriggerScheduled}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadReport(b *testing.B) {
	s, _ := Open(b.TempDir())
	e, _ := s.History.Save(rep(time.Now(), "healthy"), SaveMeta{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := s.History.Load(e.ID); err != nil {
			b.Fatal(err)
		}
	}
}
