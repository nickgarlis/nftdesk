package expr

import (
	"github.com/google/nftables/binaryutil"
	nftExpr "github.com/google/nftables/expr"
)

type ctStateP struct {
	key    nftExpr.CtKey
	states []CtState
}

func CtStateExpr() *ctStateP {
	return &ctStateP{}
}

func (c *ctStateP) ToNftExprs() []nftExpr.Any {
	var stateData uint32
	for _, state := range c.states {
		stateData |= uint32(state)
	}
	mask := binaryutil.NativeEndian.PutUint32(stateData)

	return []nftExpr.Any{
		&nftExpr.Ct{Key: c.key, Register: 1},
		&nftExpr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           mask,
			Xor:            []byte{0, 0, 0, 0},
		},
	}
}

func (c *ctStateP) In(states ...CtState) *CmpExpression {
	c.states = states
	return newCompExpression(c, nftExpr.CmpOpNeq, []byte{0, 0, 0, 0})
}
