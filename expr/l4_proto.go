package expr

import (
	nftExpr "github.com/google/nftables/expr"
)

type L4Proto struct {
	key nftExpr.MetaKey
}

func L4ProtoMeta() *L4Proto {
	return &L4Proto{
		key: nftExpr.MetaKeyL4PROTO,
	}
}

func (l *L4Proto) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Meta{Key: l.key, Register: 1},
	}
}

func (l *L4Proto) Eq(proto uint8) *CmpExpression {
	return newCompExpression(l, nftExpr.CmpOpEq, []byte{proto})
}

func (l *L4Proto) Neq(proto uint8) *CmpExpression {
	return newCompExpression(l, nftExpr.CmpOpNeq, []byte{proto})
}
