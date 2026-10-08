package ingest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ip6 packs the common :: x.y test pattern into 16 bytes.
func ip6(hi, lo byte) [16]byte {
	var a [16]byte
	a[0], a[1] = hi, lo
	return a
}

// synEvent parametrises synthetic flow-event bytes in tests.
type synEvent struct {
	TS       uint64
	SrcIP4   [4]byte
	SrcIP6   [16]byte
	DstIP4   [4]byte
	DstIP6   [16]byte
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	Mark     uint32
	Payload  uint16
	HTTPSeen uint8
	H2Pre    uint8
	TLSSeen  uint8
	Family   uint8
	Path     string
}

// syntheticEvent encodes one record in the wire layout decode.go pins.
func syntheticEvent(e synEvent) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, nativeEndian, e.TS)
	b.Write(e.SrcIP4[:])
	b.Write(e.SrcIP6[:])
	b.Write(e.DstIP4[:])
	b.Write(e.DstIP6[:])
	_ = binary.Write(&b, nativeEndian, e.SrcPort)
	_ = binary.Write(&b, nativeEndian, e.DstPort)
	b.WriteByte(e.TCPFlags)
	_ = binary.Write(&b, nativeEndian, e.Mark)
	_ = binary.Write(&b, nativeEndian, e.Payload)
	b.WriteByte(e.HTTPSeen)
	b.WriteByte(e.H2Pre)
	b.WriteByte(e.TLSSeen)
	b.WriteByte(e.Family)

	// path hint: fixed 128B NUL-padded
	var p [128]byte
	copy(p[:], e.Path)
	b.Write(p[:])
	return b.Bytes()
}

// fakeRing is the synthetic RecordSource.
type fakeRing struct {
	recs   [][]byte
	i      int
	closed bool
}

func newFakeRing(recs ...[]byte) *fakeRing { return &fakeRing{recs: recs} }

func (f *fakeRing) Recv() ([]byte, bool) {
	if f.i >= len(f.recs) {
		return nil, false
	}
	r := f.recs[f.i]
	f.i++
	return r, true
}

var (
	_ RecordSource = (*fakeRing)(nil)
	_              = errors.New
	_              = fmt.Sprintf
	_              = strings.TrimSpace
)
