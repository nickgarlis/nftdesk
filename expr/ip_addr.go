package expr

import (
	"net"

	nftExpr "github.com/google/nftables/expr"
)

type ipSelector struct{}

func IP() *ipSelector {
	return &ipSelector{}
}

func (i *ipSelector) Source() *ipMatcher {
	return &ipMatcher{
		offset: OffsetSourceIPv4,
		len:    4,
	}
}

func (i *ipSelector) Destination() *ipMatcher {
	return &ipMatcher{
		offset: OffsetDestIPv4,
		len:    4,
	}
}

type ipV6Selector struct{}

func IPv6() *ipV6Selector {
	return &ipV6Selector{}
}

func (i *ipV6Selector) Source() *ipMatcher {
	return &ipMatcher{
		offset: OffsetSourceIPv6,
		len:    16,
	}
}

func (i *ipV6Selector) Destination() *ipMatcher {
	return &ipMatcher{
		offset: OffsetDestIPv6,
		len:    16,
	}
}

type ipMatcher struct {
	offset Offset
	len    uint32
}

func (i *ipMatcher) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Payload{
			DestRegister: 1,
			Base:         nftExpr.PayloadBaseNetworkHeader,
			Offset:       uint32(i.offset),
			Len:          i.len,
		},
	}
}

func (i *ipMatcher) Eq(addr net.IP) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpEq, addr.To4())
}

func (i *ipMatcher) Neq(addr net.IP) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpNeq, addr.To4())
}

func (i *ipMatcher) InSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(i, id, name, false)
}

func (i *ipMatcher) NotInSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(i, id, name, true)
}

func (i *ipMatcher) InNamedSet(name string) *LookupExpression {
	return newLookupExpression(i, 0, name, false)
}

func (i *ipMatcher) NotInNamedSet(name string) *LookupExpression {
	return newLookupExpression(i, 0, name, true)
}

func (i *ipMatcher) InAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", false)
}

func (i *ipMatcher) NotInAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", true)
}

func (i *ipMatcher) InNetwork(network *net.IPNet) *NetworkExpression {
	return newNetworkExpression(i, nftExpr.CmpOpEq, network)
}
