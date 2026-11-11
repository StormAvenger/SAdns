package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
)

func TestCommittedSchemaIsCurrent(t *testing.T) {
	want, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../docs/schema/report.schema.json")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("docs/schema/report.schema.json is out of date: run `go run ./tools/schemagen > docs/schema/report.schema.json`")
	}
}

// Every top-level field a real report emits is described by the schema.
func TestSchemaCoversReport(t *testing.T) {
	b, _ := Generate()
	var doc struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}
	_ = json.Unmarshal(b, &doc)
	rb, _ := json.Marshal(model.Report{Schema: "sadns/report/v1", StartedAt: time.Now(), Cancelled: true})
	var rep map[string]any
	_ = json.Unmarshal(rb, &rep)
	for k := range rep {
		if _, ok := doc.Properties[k]; !ok {
			t.Errorf("schema missing %q", k)
		}
	}
	if len(doc.Required) == 0 {
		t.Error("no required fields")
	}
}
