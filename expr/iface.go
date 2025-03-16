package expr

import (
	nftExpr "github.com/google/nftables/expr"
)

type IfaceMatcher struct {
	key nftExpr.MetaKey
}

func Iface() *IfaceMatcher {
	return &IfaceMatcher{
		key: nftExpr.MetaKeyIIFNAME,
	}
}

func (i *IfaceMatcher) Input() *IfaceMatcher {
	i.key = nftExpr.MetaKeyIIFNAME
	return i
}

func (i *IfaceMatcher) Output() *IfaceMatcher {
	i.key = nftExpr.MetaKeyOIFNAME
	return i
}

func (i *IfaceMatcher) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Meta{Key: i.key, Register: 1},
	}
}

func (i *IfaceMatcher) Eq(iface string) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpEq, []byte(iface+"\x00"))
}

func (i *IfaceMatcher) Neq(iface string) *CmpExpression {
	return newCompExpression(i, nftExpr.CmpOpNeq, []byte(iface+"\x00"))
}
