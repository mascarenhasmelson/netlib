// Command arpc provides a simple ARP client which can be used to retrieve
// hardware addresses of other machines in a LAN using their IPv4 address.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/mascarenhasmelson/netlib/arp"
)

var (
	// durFlag is used to set a timeout for each ARP request
	durFlag = flag.Duration("d", 1*time.Second, "time to wait for a reply to each request")

	// retriesFlag is used to set how many requests are sent before giving up
	retriesFlag = flag.Int("r", 3, "number of requests to send before giving up")

	// ifaceFlag is used to set a network interface for ARP requests
	ifaceFlag = flag.String("i", "eth0", "network interface to use for ARP request")

	// ipFlag is used to set an IPv4 address destination for an ARP request
	ipFlag = flag.String("ip", "", "IPv4 address destination for ARP request")
)

func main() {
	flag.Parse()

	// Validate the target address before touching the network
	ip, err := netip.ParseAddr(*ipFlag)
	if err != nil || !ip.Is4() {
		log.Fatalf("invalid IPv4 address: %q (use -ip)", *ipFlag)
	}

	// Ensure valid network interface
	ifi, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatal(err)
	}

	// Set up ARP client with socket
	c, err := arp.Dial(ifi)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Request hardware address for IP address, resending lost requests
	mac, err := c.ResolveContext(context.Background(), ip, &arp.ResolveOptions{
		Attempts: *retriesFlag,
		Interval: *durFlag,
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s -> %s\n", ip, mac)
}
