// Command arp shows the ways to use the arp package:
//
//   - Building and parsing ARP packets, which works on any operating system.
//   - On a live network interface, which needs Linux and root (or
//     CAP_NET_RAW): resolving a MAC address with retries, scanning the whole
//     subnet, and checking whether an address is free (RFC 5227).
//
// Usage:
//
//	go run ./examples/arp
//	sudo ./arp -i eth0 -ip 192.168.1.1          # resolve one address
//	sudo ./arp -i eth0 -scan                    # find every device
//	sudo ./arp -i eth0 -probe 192.168.1.50      # is the address free?
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/mascarenhasmelson/netlib/arp"
	"github.com/mascarenhasmelson/netlib/ethernet"
)

func main() {
	iface := flag.String("i", "", "network interface for live examples (Linux only)")
	target := flag.String("ip", "", "IPv4 address to resolve on the live network")
	scan := flag.Bool("scan", false, "scan the interface's subnet for devices")
	probe := flag.String("probe", "", "IPv4 address to check for conflicts")
	flag.Parse()

	offline()

	if *iface == "" {
		return
	}
	c := dial(*iface)
	defer c.Close()

	if *target != "" {
		resolve(c, *target)
	}
	if *scan {
		scanSubnet(c)
	}
	if *probe != "" {
		probeAddr(c, *probe)
	}
}

// offline builds an ARP request and reply, wraps them in Ethernet frames and
// parses them back, without touching the network.
func offline() {
	myMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	myIP := netip.MustParseAddr("192.168.1.10")
	routerMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xfe}
	routerIP := netip.MustParseAddr("192.168.1.1")

	// "Who has 192.168.1.1? Tell 192.168.1.10", sent to everyone.
	req, err := arp.NewPacket(arp.OperationRequest, myMAC, myIP, ethernet.Broadcast, routerIP)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("request: who-has %s tell %s\n", req.TargetIP, req.SenderIP)

	// An ARP packet travels inside an Ethernet frame with EtherType 0x0806.
	payload, err := req.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	frame := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      myMAC,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     payload,
	}
	wire, err := frame.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("on the wire: %d bytes (28 byte ARP packet + header + padding)\n", len(wire))

	// The router's side: parse the frame, then the ARP packet inside it.
	var gotFrame ethernet.Frame
	if err := gotFrame.UnmarshalBinary(wire); err != nil {
		log.Fatal(err)
	}
	var gotReq arp.Packet
	if err := gotReq.UnmarshalBinary(gotFrame.Payload); err != nil {
		log.Fatal(err)
	}

	// "192.168.1.1 is-at 02:00:00:00:00:fe", sent back to the asker.
	reply, err := arp.NewPacket(arp.OperationReply, routerMAC, routerIP, gotReq.SenderHardwareAddr, gotReq.SenderIP)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("reply:   %s is-at %s (%s)\n", reply.SenderIP, reply.SenderHardwareAddr, reply.Operation)
}

// dial opens an ARP client on a real interface using a raw socket.
func dial(iface string) *arp.Client {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatal(err)
	}
	c, err := arp.Dial(ifi)
	if err != nil {
		log.Fatal(err) // "packet: not implemented on windows" outside Linux
	}
	fmt.Printf("live:    using %s, %s/%d\n", c.InterfaceName(), c.IP(), c.LocalPrefix().Bits())
	return c
}

// resolve finds the MAC address of one IPv4 address.
func resolve(c *arp.Client, target string) {
	ip, err := netip.ParseAddr(target)
	if err != nil || !ip.Is4() {
		log.Fatalf("invalid IPv4 address %q", target)
	}

	// Classic Resolve: one request, bounded by a deadline.
	if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		log.Fatal(err)
	}
	mac, err := c.Resolve(ip)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("live:    %s is-at %s (Resolve)\n", ip, mac)
	if err := c.SetDeadline(time.Time{}); err != nil {
		log.Fatal(err)
	}

	// ResolveContext: resends lost requests and honours a context.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mac, err = c.ResolveContext(ctx, ip, &arp.ResolveOptions{Attempts: 3, Interval: time.Second})
	if errors.Is(err, arp.ErrNoResponse) {
		fmt.Printf("live:    %s did not answer\n", ip)
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("live:    %s is-at %s (ResolveContext)\n", ip, mac)
}

// scanSubnet finds every device on the interface's subnet.
func scanSubnet(c *arp.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	start := time.Now()
	results, err := c.Scan(ctx, c.LocalPrefix(), nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("scan:    %d devices on %s in %s\n", len(results), c.LocalPrefix(), time.Since(start).Round(time.Millisecond))
	for _, r := range results {
		conflict := ""
		if len(r.Duplicates) > 0 {
			conflict = fmt.Sprintf("  IP CONFLICT with %v", r.Duplicates)
		}
		fmt.Printf("scan:      %-15s %s%s\n", r.IP, r.HardwareAddr, conflict)
	}
}

// probeAddr checks whether an address is free before using it.
func probeAddr(c *arp.Client, target string) {
	ip, err := netip.ParseAddr(target)
	if err != nil || !ip.Is4() {
		log.Fatalf("invalid IPv4 address %q", target)
	}

	err = c.Probe(context.Background(), ip, nil)
	var conflict *arp.ConflictError
	switch {
	case errors.As(err, &conflict):
		fmt.Printf("probe:   %s is IN USE by %s\n", ip, conflict.HardwareAddr)
	case err != nil:
		log.Fatal(err)
	default:
		fmt.Printf("probe:   %s is free\n", ip)
		// To claim it, announce it (only for addresses you own):
		// c.Announce(context.Background(), ip, nil)
	}
}
