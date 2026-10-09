// Package pcap reads and writes packet capture files in the classic libpcap
// format (.pcap), the format used by tcpdump and readable by Wireshark.
//
// It is pure Go and works on every operating system. Combine it with package
// packet to save live captures, or with package ethernet to decode frames
// from existing capture files.
package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// A LinkType identifies the kind of frames stored in a capture file.
// Values are assigned by tcpdump.org.
type LinkType uint32

// Common link types.
const (
	LinkTypeNull     LinkType = 0   // BSD loopback
	LinkTypeEthernet LinkType = 1   // Ethernet II frames
	LinkTypeRaw      LinkType = 101 // raw IPv4 or IPv6 packets, no link header
	LinkType80211    LinkType = 105 // IEEE 802.11 wireless frames
	LinkTypeLinuxSLL LinkType = 113 // Linux "cooked" capture (packet.Datagram sockets)
)

// DefaultSnapLen is the snapshot length NewWriter uses when given zero. It is
// the value tcpdump uses and is larger than any normal frame.
const DefaultSnapLen = 262144

// maxRecordLen limits how much memory a single record may claim, so corrupt
// files cannot trigger huge allocations.
const maxRecordLen = 1 << 24

// Magic numbers identifying the file format and timestamp precision.
const (
	magicMicroseconds = 0xa1b2c3d4
	magicNanoseconds  = 0xa1b23c4d
)

// File format version written by Writer.
const (
	versionMajor = 2
	versionMinor = 4
)

// Errors returned when reading a capture file.
var (
	// ErrNotPcap is returned by NewReader when the input does not start
	// with a pcap file header. pcapng files also return this error.
	ErrNotPcap = errors.New("pcap: not a pcap file")

	// ErrRecordTooLarge is returned when a record claims to be larger than
	// the file's snapshot length allows.
	ErrRecordTooLarge = errors.New("pcap: record too large")
)

// CaptureInfo describes one captured packet.
type CaptureInfo struct {
	// Timestamp is when the packet was captured.
	Timestamp time.Time

	// CaptureLength is the number of bytes stored in the file. It is
	// smaller than Length if the packet was truncated to the snapshot length.
	CaptureLength int

	// Length is the original length of the packet on the wire.
	Length int
}

// WriterOptions configures NewWriter. A nil *WriterOptions uses the defaults.
type WriterOptions struct {
	// LinkType is the type of every packet in the file.
	// Zero means LinkTypeEthernet, so LinkTypeNull cannot be selected.
	LinkType LinkType

	// SnapLen is the maximum number of bytes stored per packet; longer
	// packets are truncated. Zero means DefaultSnapLen.
	SnapLen int

	// Nanosecond stores timestamps with nanosecond instead of microsecond
	// precision. Wireshark and tcpdump read both.
	Nanosecond bool
}

// A Writer writes packets to a pcap file.
type Writer struct {
	w        io.Writer
	snapLen  int
	nano     bool
	linkType LinkType
	hdr      [16]byte
}

// NewWriter writes a pcap file header to w and returns a Writer that appends
// packets to it. To create a file:
//
//	f, err := os.Create("capture.pcap")
//	w, err := pcap.NewWriter(f, nil)
func NewWriter(w io.Writer, opts *WriterOptions) (*Writer, error) {
	pw := &Writer{w: w, snapLen: DefaultSnapLen, linkType: LinkTypeEthernet}
	if opts != nil {
		if opts.LinkType != 0 {
			pw.linkType = opts.LinkType
		}
		if opts.SnapLen > 0 {
			pw.snapLen = opts.SnapLen
		}
		pw.nano = opts.Nanosecond
	}

	magic := uint32(magicMicroseconds)
	if pw.nano {
		magic = magicNanoseconds
	}

	var b [24]byte
	binary.LittleEndian.PutUint32(b[0:4], magic)
	binary.LittleEndian.PutUint16(b[4:6], versionMajor)
	binary.LittleEndian.PutUint16(b[6:8], versionMinor)
	// b[8:16]: time zone offset and timestamp accuracy, always zero.
	binary.LittleEndian.PutUint32(b[16:20], uint32(pw.snapLen))
	binary.LittleEndian.PutUint32(b[20:24], uint32(pw.linkType))

	if _, err := w.Write(b[:]); err != nil {
		return nil, err
	}
	return pw, nil
}

// LinkType returns the link type written in the file header.
func (w *Writer) LinkType() LinkType { return w.linkType }

// WritePacket appends one packet captured at time ts. Data longer than the
// snapshot length is truncated, and the record keeps the original length.
func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	return w.WritePacketInfo(CaptureInfo{Timestamp: ts, Length: len(data)}, data)
}

// WritePacketInfo appends one packet with explicit capture details. If
// ci.Length is smaller than len(data), len(data) is used. ci.CaptureLength is
// ignored: it is always the number of bytes actually written.
func (w *Writer) WritePacketInfo(ci CaptureInfo, data []byte) error {
	orig := max(ci.Length, len(data))
	if len(data) > w.snapLen {
		data = data[:w.snapLen]
	}

	frac := uint32(ci.Timestamp.Nanosecond())
	if !w.nano {
		frac /= 1000
	}

	binary.LittleEndian.PutUint32(w.hdr[0:4], uint32(ci.Timestamp.Unix()))
	binary.LittleEndian.PutUint32(w.hdr[4:8], frac)
	binary.LittleEndian.PutUint32(w.hdr[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(w.hdr[12:16], uint32(orig))

	if _, err := w.w.Write(w.hdr[:]); err != nil {
		return err
	}
	_, err := w.w.Write(data)
	return err
}

// A Reader reads packets from a pcap file. It accepts both byte orders and
// both microsecond and nanosecond timestamps.
type Reader struct {
	r        io.Reader
	order    binary.ByteOrder
	nano     bool
	snapLen  int
	linkType LinkType
	major    uint16
	minor    uint16
	hdr      [16]byte
}

// NewReader reads and checks the pcap file header from r.
func NewReader(r io.Reader) (*Reader, error) {
	var b [24]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotPcap
		}
		return nil, err
	}

	pr := &Reader{r: r}
	switch {
	case binary.LittleEndian.Uint32(b[0:4]) == magicMicroseconds:
		pr.order = binary.LittleEndian
	case binary.LittleEndian.Uint32(b[0:4]) == magicNanoseconds:
		pr.order, pr.nano = binary.LittleEndian, true
	case binary.BigEndian.Uint32(b[0:4]) == magicMicroseconds:
		pr.order = binary.BigEndian
	case binary.BigEndian.Uint32(b[0:4]) == magicNanoseconds:
		pr.order, pr.nano = binary.BigEndian, true
	default:
		return nil, ErrNotPcap
	}

	pr.major = pr.order.Uint16(b[4:6])
	pr.minor = pr.order.Uint16(b[6:8])
	if pr.major != versionMajor {
		return nil, fmt.Errorf("%w: unsupported version %d.%d", ErrNotPcap, pr.major, pr.minor)
	}

	// The upper bits of the link type field may carry FCS flags.
	pr.linkType = LinkType(pr.order.Uint32(b[20:24]) & 0x0fffffff)

	snap := pr.order.Uint32(b[16:20])
	if snap == 0 || snap > maxRecordLen {
		snap = maxRecordLen
	}
	pr.snapLen = int(snap)

	return pr, nil
}

// LinkType returns the link type of the packets in the file.
func (r *Reader) LinkType() LinkType { return r.linkType }

// SnapLen returns the snapshot length from the file header.
func (r *Reader) SnapLen() int { return r.snapLen }

// Nanosecond reports whether the file stores nanosecond timestamps.
func (r *Reader) Nanosecond() bool { return r.nano }

// Version returns the file format version, normally 2.4.
func (r *Reader) Version() (major, minor int) { return int(r.major), int(r.minor) }

// ReadPacket returns the next packet in the file. It returns io.EOF after the
// last packet, and io.ErrUnexpectedEOF if the file ends inside a packet.
func (r *Reader) ReadPacket() ([]byte, CaptureInfo, error) {
	if _, err := io.ReadFull(r.r, r.hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, CaptureInfo{}, io.ErrUnexpectedEOF
		}
		return nil, CaptureInfo{}, err
	}

	sec := int64(r.order.Uint32(r.hdr[0:4]))
	frac := int64(r.order.Uint32(r.hdr[4:8]))
	capLen := r.order.Uint32(r.hdr[8:12])
	origLen := r.order.Uint32(r.hdr[12:16])

	// Some writers store records slightly longer than the snapshot length, so
	// only refuse records that could not come from a real capture.
	if capLen > uint32(max(r.snapLen, 65535)) || capLen > maxRecordLen {
		return nil, CaptureInfo{}, fmt.Errorf("%w: %d bytes", ErrRecordTooLarge, capLen)
	}

	if !r.nano {
		frac *= 1000
	}

	data := make([]byte, capLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, CaptureInfo{}, err
	}

	return data, CaptureInfo{
		Timestamp:     time.Unix(sec, frac),
		CaptureLength: int(capLen),
		Length:        int(max(origLen, capLen)),
	}, nil
}
