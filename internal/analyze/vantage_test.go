package analyze

import (
	"strings"
	"testing"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
	"github.com/StormAvenger/SAdns/internal/sysinfo"
	"github.com/StormAvenger/SAdns/internal/vantage"
)

func TestContainerBridgeNeverReadsAsHost(t *testing.T) {
	r := &model.Report{Schema: "sadns/report/v1", StartedAt: time.Now(), System: &sysinfo.Info{},
		Network: model.NetHealth{Pings: []model.Ping{{Label: "Default gateway (IPv4) — LAN / Wi-Fi quality", Target: "172.17.0.1", Family: 4, Sent: 10, Received: 7, LossPct: 30, AvgMS: 0.2}}},
		Vantage: model.Vantage{Mode: vantage.ContainerBridge, InContainer: true, Runtime: "docker", Detection: "test",
			Note: "bridge", Unavailable: []string{"router tests"}}}
	Run(r)
	var found bool
	for _, f := range r.Findings {
		if f.ID == "VANTAGE-CONTAINER" {
			found = true
			if f.Confidence != "confirmed" {
				t.Errorf("confidence %s", f.Confidence)
			}
		}
		if (f.Layer == "lan" || f.Layer == "gateway") && f.Severity != model.Info && !strings.Contains(f.Detail, "Container view") {
			t.Errorf("LAN/gateway finding not labelled as container view: %s", f.ID)
		}
	}
	if !found {
		t.Fatal("no VANTAGE-CONTAINER finding")
	}
	names := map[string]string{}
	for _, l := range r.Summary.Layers {
		names[l.Key] = l.Name
	}
	if names["gateway"] != "Docker bridge" || names["device"] != "Container" || names["lan"] != "Container network" {
		t.Errorf("layer names %v", names)
	}
	gap := false
	for _, g := range r.Summary.Coverage {
		if strings.Contains(g, "router tests") {
			gap = true
		}
	}
	if !gap {
		t.Errorf("coverage gaps %v", r.Summary.Coverage)
	}
	if r.Summary.Verdict == "healthy" {
		t.Error("container view must not produce an unqualified healthy verdict")
	}
}

func TestHostVantageUnchanged(t *testing.T) {
	r := &model.Report{Schema: "sadns/report/v1", StartedAt: time.Now(), System: &sysinfo.Info{}, Vantage: model.Vantage{Mode: vantage.Host}}
	Run(r)
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "VANTAGE-") {
			t.Errorf("unexpected %s on host", f.ID)
		}
	}
	for _, l := range r.Summary.Layers {
		if l.Key == "gateway" && l.Name != "Router" {
			t.Errorf("host gateway renamed: %s", l.Name)
		}
	}
}
