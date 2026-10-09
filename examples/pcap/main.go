// Command pcap shows how to write and read .pcap capture files with the pcap
// package, and how to decode the frames inside them with the ethernet and arp
// packages. It runs on any operating system.
//
// Usage:
//
//	go run ./examples/pcap                 # write demo.pcap, then read it back
//	go run ./examples/pcap -r capture.pcap # decode an existing capture
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/mascarenhasmelson/netlib/arp"
	"github.com/mascarenhasmelson/netlib/ethernet"
	"github.com/mascarenhasmelson/netlib/pcap"
)

func main() {
	read := flag.String("r", "", "pcap file to decode (default: write and decode demo.pcap)")
	flag.Parse()

	file := *read
	if file == "" {
		file = "demo.pcap"
		writeDemo(file)
	}
	decode(file)
}

// writeDemo creates a capture file holding an ARP request, its reply and a
// VLAN tagged frame.
func writeDemo(name string) {
	f, err := os.Create(name)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	w, err := pcap.NewWriter(f, &pcap.WriterOptions{LinkType: pcap.LinkTypeEthernet})
	if err != nil {
		log.Fatal(err)
	}

	me := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	router := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xfe}
	myIP, routerIP := netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.1")

	req, _ := arp.NewPacket(arp.OperationRequest, me, myIP, ethernet.Broadcast, routerIP)
	rep, _ := arp.NewPacket(arp.OperationReply, router, routerIP, me, myIP)

	frames := []*ethernet.Frame{
		arpFrame(req, ethernet.Broadcast),
		arpFrame(rep, me),
		{
			Destination: router,
			Source:      me,
			VLAN:        &ethernet.VLAN{ID: 100, Priority: ethernet.PriorityVoice},
			EtherType:   ethernet.EtherTypeIPv4,
			Payload:     []byte("voice traffic on VLAN 100"),
		},
	}

	start := time.Now()
	for i, fr := range frames {
		b, err := fr.MarshalBinary()
		if err != nil {
			log.Fatal(err)
		}
		if err := w.WritePacket(start.Add(time.Duration(i)*time.Millisecond), b); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("wrote %d frames to %s (open it in Wireshark)\n", len(frames), name)
}

func arpFrame(p *arp.Packet, dst net.HardwareAddr) *ethernet.Frame {
	b, err := p.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	return &ethernet.Frame{Destination: dst, Source: p.SenderHardwareAddr, EtherType: ethernet.EtherTypeARP, Payload: b}
}

// decode prints a one-line summary of every frame in a capture file, like
// "tcpdump -r".
func decode(name string) {
	f, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	r, err := pcap.NewReader(f)
	if err != nil {
		log.Fatal(err)
	}
	major, minor := r.Version()
	fmt.Printf("reading %s: pcap %d.%d, link type %d, snaplen %d\n", name, major, minor, r.LinkType(), r.SnapLen())
	if r.LinkType() != pcap.LinkTypeEthernet {
		log.Fatal("only Ethernet captures can be decoded by this example")
	}

	for i := 1; ; i++ {
		data, ci, err := r.ReadPacket()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		var fr ethernet.Frame
		if err := fr.UnmarshalBinary(data); err != nil {
			fmt.Printf("%3d  %s  undecodable: %v\n", i, ci.Timestamp.Format("15:04:05.000000"), err)
			continue
		}

		summary := fmt.Sprintf("%s -> %s %s", fr.Source, fr.Destination, fr.EtherType)
		if fr.VLAN != nil {
			summary += fmt.Sprintf(" vlan %d prio %d", fr.VLAN.ID, fr.VLAN.Priority)
		}
		if fr.EtherType == ethernet.EtherTypeARP {
			var p arp.Packet
			if err := p.UnmarshalBinary(fr.Payload); err == nil {
				if p.Operation == arp.OperationRequest {
					summary += fmt.Sprintf(": who-has %s tell %s", p.TargetIP, p.SenderIP)
				} else {
					summary += fmt.Sprintf(": %s is-at %s", p.SenderIP, p.SenderHardwareAddr)
				}
			}
		}
		fmt.Printf("%3d  %s  %4d bytes  %s\n", i, ci.Timestamp.Format("15:04:05.000000"), ci.Length, summary)
	}
}
