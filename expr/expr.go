package expr

import nftExpr "github.com/google/nftables/expr"

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
