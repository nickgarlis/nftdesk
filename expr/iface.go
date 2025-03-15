package expr

import (
	nftExpr "github.com/google/nftables/expr"
)

type IfaceP struct {
	key nftExpr.MetaKey
}

func IfaceMeta() *IfaceP {
	return &IfaceP{
		key: nftExpr.MetaKeyIIFNAME,
	}
}

func (i *IfaceP) OfKindInput() *IfaceP {
	i.key = nftExpr.MetaKeyIIFNAME
	return i
}

func (i *IfaceP) OfKindOutput() *IfaceP {
	i.key = nftExpr.MetaKeyOIFNAME
	return i
}

func (i *IfaceP) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Meta{Key: i.key, Register: 1},
	}
}

func (i *IfaceP) Eq(iface string) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpEq, []byte(iface+"\x00"))
}

func (i *IfaceP) Neq(iface string) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpNeq, []byte(iface+"\x00"))
}
