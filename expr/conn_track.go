package expr

import (
	"net"

	"github.com/google/nftables/binaryutil"
	nftExpr "github.com/google/nftables/expr"
)

type connTrackP struct {
}

func ConnTrack() *connTrackP {
	return &connTrackP{}
}

func (c *connTrackP) State() *ConnTrackStateExpr {
	return &ConnTrackStateExpr{
		key: nftExpr.CtKeySTATE,
	}
}

func (c *connTrackP) L3Proto() *connTrackL3ProtoExpr {
	return &connTrackL3ProtoExpr{
		key: nftExpr.CtKeyL3PROTOCOL,
	}
}

func (c *connTrackP) SourceIP() *connTrackIPExpr {
	return &connTrackIPExpr{
		// This corresponds to NFT_CT_SRC
		// IIUC, this value is depricated in favor of the new NFT_CT_SRC_IP value.
		// We continue using the old value for now to maintain compatibility with
		// older versions of netfilter.
		// https://git.netfilter.org/libnftnl/tree/include/linux/netfilter/nf_tables.h#n1122
		key:     nftExpr.CtKeySRC,
		version: 4,
	}
}

func (c *connTrackP) DestIP() *connTrackIPExpr {
	return &connTrackIPExpr{
		// Same as above, but for the destination IP.
		key:     nftExpr.CtKeyDST,
		version: 4,
	}
}

func (c *connTrackP) SourceIPv6() *connTrackIPExpr {
	return &connTrackIPExpr{
		key:     nftExpr.CtKeySRC,
		version: 6,
	}
}

func (c *connTrackP) DestIPv6() *connTrackIPExpr {
	return &connTrackIPExpr{
		key:     nftExpr.CtKeyDST,
		version: 6,
	}
}

func (c *connTrackP) L4Proto() *connTrackL4ProtoExpr {
	return &connTrackL4ProtoExpr{
		key: nftExpr.CtKeyPROTOCOL,
	}
}

func (c *connTrackP) SourcePort() *connTrackPortExpr {
	return &connTrackPortExpr{
		key: nftExpr.CtKeyPROTOSRC,
	}
}

func (c *connTrackP) DestPort() *connTrackPortExpr {
	return &connTrackPortExpr{
		key: nftExpr.CtKeyPROTODST,
	}
}

type ConnTrackStateExpr struct {
	key    nftExpr.CtKey
	states []CtState
}

func (c *ConnTrackStateExpr) In(states ...CtState) *CmpExpression {
	c.states = states
	return newCompExpression(c, nftExpr.CmpOpNeq, []byte{0, 0, 0, 0})
}

func (c *ConnTrackStateExpr) ToNftExprs() []nftExpr.Any {
	var stateData uint32
	for _, state := range c.states {
		stateData |= uint32(state)
	}
	mask := binaryutil.NativeEndian.PutUint32(stateData)

	return []nftExpr.Any{
		&nftExpr.Ct{Key: c.key, Register: 1},
		&nftExpr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           mask,
			Xor:            []byte{0, 0, 0, 0},
		},
	}
}

type connTrackIPExpr struct {
	key     nftExpr.CtKey
	version int
}

func (c *connTrackIPExpr) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Ct{Key: c.key, Register: 1},
	}
}

func (c *connTrackIPExpr) Eq(ip net.IP) *CmpExpression {
	if c.version == 4 {
		return newCompExpression(c, nftExpr.CmpOpEq, ip.To4())
	}
	return newCompExpression(c, nftExpr.CmpOpEq, ip.To16())
}

type connTrackL4ProtoExpr struct {
	key nftExpr.CtKey
}

func (c *connTrackL4ProtoExpr) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Ct{Key: c.key, Register: 1},
	}
}

func (c *connTrackL4ProtoExpr) Eq(proto uint8) *CmpExpression {
	return newCompExpression(c, nftExpr.CmpOpEq, []byte{proto})
}

type connTrackPortExpr struct {
	key nftExpr.CtKey
}

func (c *connTrackPortExpr) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Ct{Key: c.key, Register: 1},
	}
}

func (c *connTrackPortExpr) Eq(port uint16) *CmpExpression {
	return newCompExpression(c, nftExpr.CmpOpEq, binaryutil.BigEndian.PutUint16(port))
}

type connTrackL3ProtoExpr struct {
	key nftExpr.CtKey
}

func (c *connTrackL3ProtoExpr) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Ct{Key: c.key, Register: 1},
	}
}

func (c *connTrackL3ProtoExpr) Eq(proto uint8) *CmpExpression {
	return newCompExpression(c, nftExpr.CmpOpEq, []byte{proto})
}
