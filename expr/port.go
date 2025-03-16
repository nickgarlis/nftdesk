package expr

import (
	nftExpr "github.com/google/nftables/expr"
	"github.com/nickgarlis/nftdesk/internal"
)

type portSelector struct{}

func Port() *portSelector {
	return &portSelector{}
}
func (p *portSelector) Source() *portMatcher {
	return &portMatcher{offset: OffsetSourcePort}
}
func (p *portSelector) Destination() *portMatcher {
	return &portMatcher{offset: OffsetDestPort}
}

type portMatcher struct {
	offset Offset
}

func (p *portMatcher) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Payload{
			DestRegister: 1,
			Base:         nftExpr.PayloadBaseTransportHeader,
			Offset:       uint32(p.offset),
			Len:          2,
		},
	}
}

func (p *portMatcher) Eq(port uint16) *CmpExpression {
	return newCompExpression(p, nftExpr.CmpOpEq, internal.PortToBytes(port))
}

func (p *portMatcher) Neq(port uint16) *CmpExpression {
	return newCompExpression(p, nftExpr.CmpOpNeq, internal.PortToBytes(port))
}

func (p *portMatcher) InSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(p, id, name, false)
}

func (p *portMatcher) NotInSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(p, id, name, true)
}

func (i *portMatcher) InAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", false)
}

func (i *portMatcher) NotInAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", true)
}
