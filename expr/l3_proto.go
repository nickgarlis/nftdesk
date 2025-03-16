package expr

import (
	nftExpr "github.com/google/nftables/expr"
)

type l3ProtoMatcher struct {
	key nftExpr.MetaKey
}

// L3Proto matches the layer 3 protocol.
// It is mostly relevant for tables of family inet.
func L3Proto() *l3ProtoMatcher {
	return &l3ProtoMatcher{
		key: nftExpr.MetaKeyNFPROTO,
	}
}

func (l *l3ProtoMatcher) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Meta{Key: l.key, Register: 1},
	}
}

func (l *l3ProtoMatcher) Eq(proto uint8) *CmpExpression {
	return newCompExpression(l, nftExpr.CmpOpEq, []byte{proto})
}

func (l *l3ProtoMatcher) Neq(proto uint8) *CmpExpression {
	return newCompExpression(l, nftExpr.CmpOpNeq, []byte{proto})
}
