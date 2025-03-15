package expr

import (
	"net"

	nftExpr "github.com/google/nftables/expr"
)

type IPv6P struct {
	offset Offset
	len    uint32
}

func IPv6Payload() *IPv6P {
	return &IPv6P{
		offset: OffsetSourceIPv6,
		len:    16,
	}
}

func (i *IPv6P) OfKindSource() *IPv6P {
	i.offset = OffsetSourceIPv6
	return i
}

func (i *IPv6P) OfKindDest() *IPv6P {
	i.offset = OffsetDestIPv6
	return i
}

func (i *IPv6P) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Payload{
			DestRegister: 1,
			Base:         nftExpr.PayloadBaseNetworkHeader,
			Offset:       uint32(i.offset),
			Len:          i.len,
		},
	}
}

func (i *IPv6P) Eq(addr net.IP) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpEq, addr.To16())
}

func (i *IPv6P) Neq(addr net.IP) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpNeq, addr.To16())
}

func (i *IPv6P) InSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(i, id, name, false)
}

func (i *IPv6P) NotInSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(i, id, name, true)
}

func (i *IPv6P) InAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", false)
}

func (i *IPv6P) NotInAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", true)
}
