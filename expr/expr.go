package expr

import (
	"net"

	nftExpr "github.com/google/nftables/expr"
	"github.com/nickgarlis/nftdesk/internal"
)

type LookupExpression struct {
	left   Payload
	id     uint32
	name   string
	invert bool
}

func (l *LookupExpression) ToNftExprs() []nftExpr.Any {
	return append(l.left.ToNftExprs(), &nftExpr.Lookup{
		SourceRegister: 1,
		SetName:        l.name,
		SetID:          l.id,
		Invert:         l.invert,
	})
}

func newLookupExpression(left Payload, id uint32, name string, invert bool) *LookupExpression {
	return &LookupExpression{
		left:   left,
		id:     id,
		name:   name,
		invert: invert,
	}
}

type CmpExpression struct {
	left  Payload
	op    nftExpr.CmpOp
	right []byte
}

func (c *CmpExpression) ToNftExprs() []nftExpr.Any {
	return append(c.left.ToNftExprs(), &nftExpr.Cmp{
		Op:       c.op,
		Register: 1,
		Data:     c.right,
	})
}

func newCompExpression(left Payload, op nftExpr.CmpOp, right []byte) *CmpExpression {
	return &CmpExpression{
		left:  left,
		op:    op,
		right: right,
	}
}

type NetworkExpression struct {
	left Payload
	data []byte
	mask []byte
	op   nftExpr.CmpOp
}

func (n *NetworkExpression) ToNftExprs() []nftExpr.Any {
	left := n.left.ToNftExprs()
	return append(left,
		&nftExpr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            uint32(len(n.mask)),
			Mask:           n.mask,
			Xor:            make([]byte, len(n.mask)),
		},
		&nftExpr.Cmp{
			Op:       n.op,
			Register: 1,
			Data:     n.data,
		},
	)
}

func newNetworkExpression(left Payload, op nftExpr.CmpOp, network *net.IPNet) *NetworkExpression {
	data := internal.NetIPToBytes(network.IP)
	mask := internal.NetIPToBytes(net.IP(network.Mask))
	return &NetworkExpression{
		left: left,
		data: data,
		mask: mask,
		op:   op,
	}
}
