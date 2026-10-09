// Command vlan shows how to add and read IEEE 802.1Q VLAN tags, including
// 802.1ad double tagging (Q-in-Q). It runs on any operating system.
package main

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/mascarenhasmelson/netlib/ethernet"
)

func main() {
	src := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	// 1. Single VLAN tag: VLAN 100 with voice priority.
	tagged := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      src,
		VLAN: &ethernet.VLAN{
			Priority: ethernet.PriorityVoice, // 802.1p priority 0-7
			ID:       100,                    // VLAN ID 1-4094
		},
		EtherType: ethernet.EtherTypeIPv4,
		Payload:   []byte("tagged"),
	}
	b, err := tagged.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	// Bytes 12-15 are the tag: TPID 0x8100, then priority/DEI/ID.
	fmt.Printf("802.1Q tag bytes: % x\n", b[12:16])

	var f ethernet.Frame
	if err := f.UnmarshalBinary(b); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decoded VLAN %d, priority %d, inner type %s\n",
		f.VLAN.ID, f.VLAN.Priority, f.EtherType)

	// 2. Q-in-Q: a service provider tag (S-VLAN) wrapping a customer tag
	// (C-VLAN). ServiceVLAN always requires VLAN to be set too.
	qinq := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      src,
		ServiceVLAN: &ethernet.VLAN{ID: 300},
		VLAN:        &ethernet.VLAN{ID: 100, DropEligible: true},
		EtherType:   ethernet.EtherTypeARP,
	}
	b, err = qinq.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	if err := f.UnmarshalBinary(b); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Q-in-Q: S-VLAN %d, C-VLAN %d (drop eligible %t), inner type %s\n",
		f.ServiceVLAN.ID, f.VLAN.ID, f.VLAN.DropEligible, f.EtherType)

	// 3. Encoding a single VLAN tag on its own.
	tag, err := (&ethernet.VLAN{Priority: ethernet.PriorityVideo, ID: 42}).MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("standalone tag for VLAN 42 / priority 4: % x\n", tag)

	// 4. Validation: IDs above 4094 or priorities above 7 are rejected.
	bad := &ethernet.Frame{VLAN: &ethernet.VLAN{ID: 4095}}
	if _, err := bad.MarshalBinary(); errors.Is(err, ethernet.ErrInvalidVLAN) {
		fmt.Println("VLAN 4095 rejected:", err)
	}
}
