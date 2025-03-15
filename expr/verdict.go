package expr

import (
	nftExpr "github.com/google/nftables/expr"
)

type verdictP struct {
	kind  nftExpr.VerdictKind
	chain string
}

func VerdictExpr() *verdictP {
	return &verdictP{
		kind: nftExpr.VerdictAccept,
	}
}

func (v *verdictP) ofKind(kind nftExpr.VerdictKind, chain string) *verdictP {
	v.kind = kind
	v.chain = chain
	return v
}

func (v *verdictP) OfKindAccept() *verdictP {
	return v.ofKind(nftExpr.VerdictAccept, "")
}

func (v *verdictP) OfKindDrop() *verdictP {
	return v.ofKind(nftExpr.VerdictDrop, "")
}

func (v *verdictP) OfKindReturn() *verdictP {
	return v.ofKind(nftExpr.VerdictReturn, "")
}

func (v *verdictP) OfKindJump(chain string) *verdictP {
	return v.ofKind(nftExpr.VerdictJump, chain)
}

func (v *verdictP) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Verdict{
			Kind:  v.kind,
			Chain: v.chain,
		},
	}
}
