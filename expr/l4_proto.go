package expr

import (
	nftExpr "github.com/google/nftables/expr"
)

type l4ProtoP struct {
	key nftExpr.MetaKey
}

func L4Proto() *l4ProtoP {
	return &l4ProtoP{
		key: nftExpr.MetaKeyL4PROTO,
	}
}

func (l *l4ProtoP) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Meta{Key: l.key, Register: 1},
	}
}

func (l *l4ProtoP) Eq(proto uint8) *CmpExpression {
	return newCompExpression(l, nftExpr.CmpOpEq, []byte{proto})
}

func (l *l4ProtoP) Neq(proto uint8) *CmpExpression {
	return newCompExpression(l, nftExpr.CmpOpNeq, []byte{proto})
}
