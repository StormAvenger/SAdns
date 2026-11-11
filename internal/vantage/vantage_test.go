package vantage

import (
	"errors"
	"testing"
)

type env struct {
	vars  map[string]string
	files map[string]string
	ifs   []string
	goos  string
}

func (e env) probe() Probe {
	return Probe{
		Getenv: func(k string) string { return e.vars[k] },
		Exists: func(p string) bool { _, ok := e.files[p]; return ok },
		ReadFile: func(p string) ([]byte, error) {
			if s, ok := e.files[p]; ok {
				return []byte(s), nil
			}
			return nil, errors.New("nope")
		},
		Interfaces: func() ([]string, error) { return e.ifs, nil },
		GOOS:       e.goos,
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		e    env
		gws  []string
		mode string
		rt   string
	}{
		{"bare linux host", env{goos: "linux", ifs: []string{"lo", "enp3s0", "docker0"}}, []string{"192.168.1.1"}, Host, ""},
		{"windows", env{goos: "windows"}, nil, Host, ""},
		{"docker bridge", env{goos: "linux", files: map[string]string{"/.dockerenv": ""}, ifs: []string{"lo", "eth0"}}, []string{"172.17.0.1"}, ContainerBridge, "docker"},
		{"docker user bridge", env{goos: "linux", files: map[string]string{"/.dockerenv": ""}, ifs: []string{"lo", "eth0"}}, []string{"172.20.0.1"}, ContainerBridge, "docker"},
		{"docker host net", env{goos: "linux", files: map[string]string{"/.dockerenv": ""}, ifs: []string{"lo", "enp3s0", "docker0", "veth12"}}, []string{"192.168.1.1"}, ContainerHostNet, "docker"},
		{"macvlan", env{goos: "linux", files: map[string]string{"/.dockerenv": ""}, ifs: []string{"lo", "eth0"}}, []string{"192.168.1.1"}, ContainerOther, "docker"},
		{"podman", env{goos: "linux", files: map[string]string{"/run/.containerenv": ""}, ifs: []string{"lo", "eth0"}}, []string{"10.88.0.1"}, ContainerOther, "podman"},
		{"cgroup", env{goos: "linux", files: map[string]string{"/proc/1/cgroup": "0::/kubepods/besteffort/pod1"}, ifs: []string{"lo", "eth0"}}, []string{"172.17.0.1"}, ContainerBridge, "kubepods"},
		{"override host", env{goos: "linux", vars: map[string]string{"SADNS_NETWORK_MODE": "host"}, files: map[string]string{"/.dockerenv": ""}, ifs: []string{"lo", "eth0"}}, []string{"172.17.0.1"}, ContainerHostNet, "docker"},
		{"forced container", env{goos: "linux", vars: map[string]string{"SADNS_IN_CONTAINER": "1", "SADNS_NETWORK_MODE": "bridge"}}, nil, ContainerBridge, "container"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Detect(c.e.probe(), c.gws)
			if v.Mode != c.mode || v.Runtime != c.rt {
				t.Fatalf("got mode=%s runtime=%s (%s); want %s/%s", v.Mode, v.Runtime, v.Detection, c.mode, c.rt)
			}
			if v.InContainer != (c.rt != "") {
				t.Errorf("InContainer=%v", v.InContainer)
			}
			if IsContainerView(v) && (len(v.Unavailable) == 0 || v.Note == "") {
				t.Errorf("container view without explanation: %+v", v)
			}
		})
	}
}
