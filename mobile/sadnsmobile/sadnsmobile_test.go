package sadnsmobile

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StormAvenger/SAdns/internal/mockdns"
)

type rec struct {
	mu   sync.Mutex
	evs  []string
	done chan struct{}
}

func (r *rec) OnEvent(s string) {
	r.mu.Lock()
	r.evs = append(r.evs, s)
	r.mu.Unlock()
	if strings.Contains(s, `"type":"done"`) {
		close(r.done)
	}
}

func TestQuickScanOnDevice(t *testing.T) {
	m, err := mockdns.Start(mockdns.Behavior{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sc, err := NewScanner(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	if sc.HistoryJSON() != "[]" {
		t.Fatalf("empty history: %s", sc.HistoryJSON())
	}
	if err := sc.Start(`{"bogus":true}`, nil); err == nil {
		t.Fatal("unknown field accepted")
	}
	var def map[string]any
	if err := json.Unmarshal([]byte(DefaultRequestJSON()), &def); err != nil || def["quick"] != true {
		t.Fatalf("default request %v %v", def, err)
	}
	sc.SetSystemDNS(" " + m.Addr + " ,")
	r := &rec{done: make(chan struct{})}
	if err := sc.Start(`{"quick":true,"low_data":true,"no_providers":true,"ipv4":true,"ipv6":true,"timeout_ms":500,"samples":1}`, r); err != nil {
		t.Fatal(err)
	}
	if !sc.Running() {
		t.Error("not running after start")
	}
	time.Sleep(500 * time.Millisecond)
	sc.Cancel() // keep the test fast and offline-safe; partial results are saved
	select {
	case <-r.done:
	case <-time.After(30 * time.Second):
		t.Fatal("no done event")
	}
	var hist []map[string]any
	_ = json.Unmarshal([]byte(sc.HistoryJSON()), &hist)
	if len(hist) != 1 {
		t.Fatalf("history %s", sc.HistoryJSON())
	}
	id := hist[0]["id"].(string)
	js, err := sc.Report(id, "json", "public")
	if err != nil || !strings.Contains(js, SchemaVersion) || !strings.Contains(js, `"mobile"`) {
		t.Fatalf("report json: %v", err)
	}
	md, err := sc.Report("", "md", "technical")
	if err != nil || !strings.Contains(md, "SAdns") {
		t.Fatalf("report md: %v", err)
	}
	if err := sc.SetPinned(id, true); err != nil {
		t.Fatal(err)
	}
	if err := sc.Delete(id); err != nil || sc.HistoryJSON() != "[]" {
		t.Fatalf("delete: %v", err)
	}
}
