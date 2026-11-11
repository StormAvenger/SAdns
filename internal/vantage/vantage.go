// Package vantage determines where SAdns is measuring from — directly on a
// host, or inside a container — so reports never present a container's
// virtual network as the host's or the home network's.
package vantage

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"github.com/StormAvenger/SAdns/internal/model"
)

// Modes.
const (
	Host             = "host"
	ContainerBridge  = "container-bridge"
	ContainerHostNet = "container-host-network"
	ContainerOther   = "container-unknown" // macvlan/ipvlan or undetermined
)

// Probe is the environment the detector inspects; tests replace it.
type Probe struct {
	Getenv     func(string) string
	Exists     func(string) bool
	ReadFile   func(string) ([]byte, error)
	Interfaces func() ([]string, error)
	GOOS       string
}

// System returns a Probe for the real environment.
func System() Probe {
	return Probe{
		Getenv:   os.Getenv,
		Exists:   func(p string) bool { _, err := os.Stat(p); return err == nil },
		ReadFile: os.ReadFile,
		Interfaces: func() ([]string, error) {
			ifs, err := net.Interfaces()
			var n []string
			for _, i := range ifs {
				n = append(n, i.Name)
			}
			return n, err
		},
		GOOS: runtime.GOOS,
	}
}

// Detect inspects the environment. gateways are the default-route gateway
// addresses the scan found (may be empty).
func Detect(p Probe, gateways []string) model.Vantage {
	v := model.Vantage{Mode: Host}
	if p.GOOS != "linux" && p.Getenv("SADNS_IN_CONTAINER") == "" {
		v.Detection = "not Linux; containers not considered"
		return v
	}
	runtimeName, how := containerRuntime(p)
	if runtimeName == "" {
		v.Detection = "no container markers found"
		return v
	}
	v.InContainer, v.Runtime = true, runtimeName
	var why []string
	why = append(why, how)

	mode := strings.ToLower(strings.TrimSpace(p.Getenv("SADNS_NETWORK_MODE")))
	switch mode {
	case "host":
		v.Mode = ContainerHostNet
		why = append(why, "SADNS_NETWORK_MODE=host")
	case "bridge":
		v.Mode = ContainerBridge
		why = append(why, "SADNS_NETWORK_MODE=bridge")
	case "macvlan", "ipvlan", "other":
		v.Mode = ContainerOther
		why = append(why, "SADNS_NETWORK_MODE="+mode)
	default:
		v.Mode, how = guessNetwork(p, gateways)
		why = append(why, how)
	}
	v.Detection = strings.Join(why, "; ")
	switch v.Mode {
	case ContainerBridge:
		v.Note = "Measured from inside a container on a bridge network. The \"device\" is the container, the \"LAN\" is a virtual Docker network and the \"gateway\" is the Docker bridge on the host — not your router. Internet, DNS and website results reflect the host's uplink as seen through Docker's NAT and DNS forwarding."
		v.Unavailable = []string{
			"Wi-Fi / LAN link quality of the host (the gateway measured is the Docker bridge, not the router)",
			"The host's own DNS configuration (the container uses Docker's resolver settings, e.g. 127.0.0.11 on user-defined networks)",
			"Router-specific tests (router DNS, DNS rebinding protection, local encrypted DNS, double NAT on the real LAN)",
			"Host interface addresses and IPv6 (bridge networks have IPv6 disabled unless configured)",
		}
	case ContainerHostNet:
		v.Note = "Measured from a container sharing the host's network namespace: interfaces, routes and the gateway are the host's. DNS configuration is the container's copy of the host's resolv.conf, which can differ from what host applications use (e.g. systemd-resolved)."
		v.Unavailable = []string{"Host OS resolver path for local applications (container has its own resolv.conf and libc)"}
	case ContainerOther:
		v.Note = "Measured from inside a container whose network mode could not be determined (macvlan/ipvlan give the container its own address on the LAN). Treat device and LAN results as describing the container, not the host."
		v.Unavailable = []string{"The host's own network view (interfaces, DNS configuration)"}
	}
	return v
}

func containerRuntime(p Probe) (string, string) {
	if v := p.Getenv("SADNS_IN_CONTAINER"); v != "" && v != "0" && !strings.EqualFold(v, "false") {
		rt := "container"
		if p.Exists("/.dockerenv") {
			rt = "docker"
		}
		return rt, "SADNS_IN_CONTAINER set"
	}
	if p.GOOS != "linux" {
		return "", ""
	}
	if p.Exists("/.dockerenv") {
		return "docker", "/.dockerenv present"
	}
	if p.Exists("/run/.containerenv") {
		return "podman", "/run/.containerenv present"
	}
	if p.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes", "KUBERNETES_SERVICE_HOST set"
	}
	if b, err := p.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, k := range []string{"docker", "kubepods", "containerd", "libpod", "lxc"} {
			if strings.Contains(s, k) {
				return k, "/proc/1/cgroup mentions " + k
			}
		}
	}
	return "", ""
}

// guessNetwork infers the container network mode from what the container
// can see. Host networking exposes the host's interfaces (physical NICs,
// docker0, veth pairs, bridges); a bridge-networked container sees only
// loopback and one eth interface, with a gateway in Docker's default pools.
func guessNetwork(p Probe, gateways []string) (string, string) {
	names, err := p.Interfaces()
	if err != nil {
		return ContainerOther, "interfaces unreadable"
	}
	for _, n := range names {
		if n == "docker0" || strings.HasPrefix(n, "br-") || strings.HasPrefix(n, "veth") ||
			strings.HasPrefix(n, "wl") || strings.HasPrefix(n, "en") || strings.HasPrefix(n, "virbr") || strings.HasPrefix(n, "bond") {
			return ContainerHostNet, "host interfaces visible (" + n + ")"
		}
	}
	nonLo := 0
	for _, n := range names {
		if n != "lo" {
			nonLo++
		}
	}
	for _, g := range gateways {
		a, err := netip.ParseAddr(g)
		if err != nil || !a.Is4() {
			continue
		}
		if netip.MustParsePrefix("172.16.0.0/12").Contains(a) && nonLo <= 2 {
			return ContainerBridge, "only container interfaces visible and gateway " + g + " is in Docker's default bridge range"
		}
	}
	if nonLo <= 2 {
		return ContainerOther, "only container interfaces visible; gateway is not in a Docker bridge range (macvlan/ipvlan or custom bridge) — set SADNS_NETWORK_MODE to be explicit"
	}
	return ContainerOther, "network mode undetermined — set SADNS_NETWORK_MODE"
}

// IsContainerView reports whether device/LAN/gateway results describe a
// container rather than the host.
func IsContainerView(v model.Vantage) bool {
	return v.Mode == ContainerBridge || v.Mode == ContainerOther
}
