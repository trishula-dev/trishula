package shield

import "encoding/binary"

// TR-10 (issue #10): the bans_v4 wire — RED stub (GREEN lands the real
// wire structs; bpf/ban_xdp.c's map layout must match these).
type BansV4Key struct {
	SAddr [4]byte // network byte order (be32)
}

type BansV4Val struct {
	BanUntilMs uint64
}

var _ = binary.BigEndian
