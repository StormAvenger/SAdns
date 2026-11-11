package report

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/StormAvenger/SAdns/internal/model"
)

func sample(b *testing.B) *model.Report {
	raw, err := os.ReadFile("testdata/sample-public.json")
	if err != nil {
		b.Fatal(err)
	}
	var r model.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		b.Fatal(err)
	}
	return &r
}

func BenchmarkMarkdown(b *testing.B) {
	r := sample(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Markdown(r)
	}
}

func BenchmarkRedactPublic(b *testing.B) {
	r := sample(b)
	md := Markdown(r)
	b.ReportAllocs()
	b.SetBytes(int64(len(md)))
	for i := 0; i < b.N; i++ {
		_ = NewRedactor(r, PrivacyPublic).Apply(md)
	}
}

func BenchmarkJSON(b *testing.B) {
	r := sample(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := JSON(r); err != nil {
			b.Fatal(err)
		}
	}
}
