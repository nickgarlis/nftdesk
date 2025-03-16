package expr

import (
	nftExpr "github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type Offset uint32

const (
	// Source port offset in TCP/UDP header
	OffsetSourcePort Offset = 0
	// Dest port offset in TCP/UDP header
	OffsetDestPort Offset = 2
	// Source IP offset in IPv4 header
	OffsetSourceIPv4 Offset = 12
	// Dest IP offset in IPv4 header
	OffsetDestIPv4 Offset = 16
	// Source IP offset in IPv6 header
	OffsetSourceIPv6 Offset = 8 // TODO ?
	// Dest IP offset in IPv6 header
	OffsetDestIPv6 Offset = 24
)

type CtState uint32

const (
	CtStateINVALID     CtState = 1
	CtStateESTABLISHED CtState = 2
	CtStateRELATED     CtState = 4
	CtStateNEW         CtState = 8
	CtStateUNTRACKED   CtState = 64
)

const (
	L3ProtoIPV4   uint8 = unix.NFPROTO_IPV4
	L3ProtoIPV6   uint8 = unix.NFPROTO_IPV6
	L3ProtoARP    uint8 = unix.NFPROTO_ARP
	L3ProtoBRIDGE uint8 = unix.NFPROTO_BRIDGE
)

const (
	L4ProtoICMP   uint8 = unix.IPPROTO_ICMP
	L4ProtoTCP    uint8 = unix.IPPROTO_TCP
	L4ProtoUDP    uint8 = unix.IPPROTO_UDP
	L4ProtoICMPV6 uint8 = unix.IPPROTO_ICMPV6
	L4ProtoSCTP   uint8 = unix.IPPROTO_SCTP
)

type VerdictKind int64

// Verdicts, as per netfilter.h and netfilter/nf_tables.h.
const (
	VerdictReturn VerdictKind = iota - 5
	VerdictGoto
	VerdictJump
	VerdictBreak
	VerdictContinue
	VerdictDrop
	VerdictAccept
	VerdictStolen
	VerdictQueue
	VerdictRepeat
	VerdictStop
)

type Payload interface {
	ToNftExprs() []nftExpr.Any
}

type Expression interface {
	ToNftExprs() []nftExpr.Any
}
