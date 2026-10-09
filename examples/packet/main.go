// Command packet captures raw Ethernet frames on a Linux interface, like a
// tiny tcpdump. It shows packet.Listen, a BPF kernel filter, promiscuous
// mode, deadlines and socket statistics.
//
// With -w it also saves the frames to a .pcap file you can open in Wireshark.
//
// It needs Linux and root (or CAP_NET_RAW):
//
//	sudo ./packet -i eth0 -n 5
//	sudo ./packet -i eth0 -n 5 -w arp.pcap
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/mascarenhasmelson/netlib/ethernet"
	"github.com/mascarenhasmelson/netlib/packet"
	"github.com/mascarenhasmelson/netlib/pcap"
	"golang.org/x/net/bpf"
)

// etherTypeAll asks the kernel for frames of every protocol (ETH_P_ALL).
const etherTypeAll = 0x0003

func main() {
	iface := flag.String("i", "eth0", "network interface to capture on")
	count := flag.Int("n", 5, "number of ARP frames to capture")
	promisc := flag.Bool("p", false, "enable promiscuous mode (see traffic for other hosts)")
	save := flag.String("w", "", "also write captured frames to this .pcap file")
	flag.Parse()

	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatal(err)
	}

	// A BPF program runs inside the kernel and drops everything except ARP
	// frames before they reach this program. It is the same filter as
	// "tcpdump arp": load the EtherType at offset 12 and compare it.
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(ethernet.EtherTypeARP), SkipTrue: 1},
		bpf.RetConstant{Val: 65535}, // keep the whole frame
		bpf.RetConstant{Val: 0},     // drop
	})
	if err != nil {
		log.Fatal(err)
	}

	// packet.Raw gives full frames including the Ethernet header.
	// packet.Datagram would strip the header and give only the payload.
	c, err := packet.Listen(ifi, packet.Raw, etherTypeAll, &packet.Config{Filter: filter})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if *promisc {
		if err := c.SetPromiscuous(true); err != nil {
			log.Fatal(err)
		}
	}

	// Optionally record every captured frame in a pcap file.
	var pw *pcap.Writer
	if *save != "" {
		f, err := os.Create(*save)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		if pw, err = pcap.NewWriter(f, nil); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("capturing %d ARP frames on %s (%s)\n", *count, ifi.Name, ifi.HardwareAddr)

	buf := make([]byte, ifi.MTU+14)
	for captured := 0; captured < *count; {
		// Deadlines work like any net.Conn, so a quiet network cannot hang us.
		if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			log.Fatal(err)
		}
		n, from, err := c.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			fmt.Println("no ARP traffic for 10s, stopping")
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		var f ethernet.Frame
		if err := f.UnmarshalBinary(buf[:n]); err != nil {
			continue
		}
		fmt.Printf("%d bytes from %s: %s -> %s %s\n", n, from, f.Source, f.Destination, f.EtherType)
		if pw != nil {
			if err := pw.WritePacket(time.Now(), buf[:n]); err != nil {
				log.Fatal(err)
			}
		}
		captured++
	}

	// Kernel counters for this socket: frames delivered and dropped.
	if s, err := c.Stats(); err == nil {
		fmt.Printf("kernel stats: %d packets, %d drops\n", s.Packets, s.Drops)
	}

	// Sending works the same way: build a frame and write it to an address.
	// Here a frame with an unassigned EtherType is broadcast to the segment.
	out, err := (&ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      ifi.HardwareAddr,
		EtherType:   0xcccc,
		Payload:     []byte("hello from netlib"),
	}).MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.WriteTo(out, &packet.Addr{HardwareAddr: ethernet.Broadcast}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("sent one broadcast frame")
	if pw != nil {
		fmt.Println("saved capture to", *save)
	}
}
