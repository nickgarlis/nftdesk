package expr

import (
	"net"

	nftExpr "github.com/google/nftables/expr"
)

type IPv4P struct {
	offset Offset
	len    uint32
}

func IPv4Payload() *IPv4P {
	return &IPv4P{
		offset: OffsetSourceIPv4,
		len:    4,
	}
}

func (i *IPv4P) OfKindSource() *IPv4P {
	i.offset = OffsetSourceIPv4
	return i
}

func (i *IPv4P) OfKindDest() *IPv4P {
	i.offset = OffsetDestIPv4
	return i
}

func (i *IPv4P) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Payload{
			DestRegister: 1,
			Base:         nftExpr.PayloadBaseNetworkHeader,
			Offset:       uint32(i.offset),
			Len:          i.len,
		},
	}
}

func (i *IPv4P) Eq(addr net.IP) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpEq, addr.To4())
}

func (i *IPv4P) Neq(addr net.IP) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpNeq, addr.To4())
}

func (i *IPv4P) InSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(i, id, name, false)
}

func (i *IPv4P) NotInSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(i, id, name, true)
}

func (i *IPv4P) InAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", false)
}

func (i *IPv4P) NotInAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", true)
}
