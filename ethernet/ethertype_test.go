package ethernet

import (
	"net"
	"testing"
)

func TestEtherTypeString(t *testing.T) {
	tests := []struct {
		et   EtherType
		want string
	}{
		{EtherTypeIPv4, "EtherTypeIPv4"},
		{EtherTypeARP, "EtherTypeARP"},
		{EtherTypeIPv6, "EtherTypeIPv6"},
		{EtherTypeVLAN, "EtherTypeVLAN"},
		{EtherTypeServiceVLAN, "EtherTypeServiceVLAN"},
		{EtherTypeWakeOnLAN, "EtherTypeWakeOnLAN"},
		{EtherTypeRARP, "EtherTypeRARP"},
		{EtherTypeLLDP, "EtherTypeLLDP"},
		{EtherTypeEAPOL, "EtherTypeEAPOL"},
		{EtherTypeMPLSUnicast, "EtherTypeMPLSUnicast"},
		{EtherTypeMPLSMulticast, "EtherTypeMPLSMulticast"},
		{EtherTypePPPoEDiscovery, "EtherTypePPPoEDiscovery"},
		{EtherTypePPPoESession, "EtherTypePPPoESession"},
		{EtherTypePTP, "EtherTypePTP"},
		{EtherTypeMACsec, "EtherTypeMACsec"},
		{EtherTypeSlowProtocols, "EtherTypeSlowProtocols"},
		{EtherTypeMACControl, "EtherTypeMACControl"},
		{EtherTypeFCoE, "EtherTypeFCoE"},
		{EtherTypeRoCE, "EtherTypeRoCE"},
		{EtherTypeQinQ, "EtherTypeQinQ"},
		{EtherTypeLoopback, "EtherTypeLoopback"},
		{0xcccc, "EtherType(52428)"},
	}
	for _, tt := range tests {
		if got := tt.et.String(); got != tt.want {
			t.Errorf("EtherType(%#04x).String() = %q, want %q", uint16(tt.et), got, tt.want)
		}
	}
}

func TestEtherTypeValues(t *testing.T) {
	// Guard against typos in the registered values.
	tests := map[EtherType]uint16{
		EtherTypeWakeOnLAN:      0x0842,
		EtherTypeLLDP:           0x88cc,
		EtherTypeEAPOL:          0x888e,
		EtherTypePTP:            0x88f7,
		EtherTypeMPLSUnicast:    0x8847,
		EtherTypePPPoEDiscovery: 0x8863,
		EtherTypePPPoESession:   0x8864,
		EtherTypeMACsec:         0x88e5,
	}
	for et, want := range tests {
		if uint16(et) != want {
			t.Errorf("%s = %#04x, want %#04x", et, uint16(et), want)
		}
	}
}

func TestEtherTypeRoundTrip(t *testing.T) {
	// A frame using a newly named EtherType survives encode and decode.
	f := &Frame{
		Destination: net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}, // LLDP multicast
		Source:      net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		EtherType:   EtherTypeLLDP,
		Payload:     []byte{0x02, 0x07, 0x04},
	}
	b, err := f.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got Frame
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if got.EtherType != EtherTypeLLDP || got.EtherType.String() != "EtherTypeLLDP" {
		t.Fatalf("got %s", got.EtherType)
	}
}
