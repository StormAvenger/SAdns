// Command mockdns starts local mock resolvers for offline development of
// SAdns (UI work, report formatting). Not shipped in releases.
//
//	go run ./tools/mockdns
package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/StormAvenger/SAdns/internal/mockdns"
)

func main() {
	good, err := mockdns.Start(mockdns.Behavior{Validating: true, Filtering: true, Version: "dnsmasq-2.90", Egress: "203.0.113.7", ASN: "13335"})
	if err != nil {
		panic(err)
	}
	bad, err := mockdns.Start(mockdns.Behavior{HijackNX: true, NoTCP: true, DropLargeUDP: true, Egress: "198.51.100.9", ASN: "64501"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("healthy (validating, ad-blocking dnsmasq): %s\n", good.Addr)
	fmt.Printf("broken  (NXDOMAIN hijack, no TCP, drops big UDP): %s\n", bad.Addr)
	fmt.Printf("\ntry: go run ./cmd/sadns run --providers none --resolver %s,%s\n", good.Addr, bad.Addr)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
