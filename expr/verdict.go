package expr

import (
	nftExpr "github.com/google/nftables/expr"
)

type verdictP struct {
	kind  nftExpr.VerdictKind
	chain string
}

func Verdict() *verdictP {
	return &verdictP{
		kind: nftExpr.VerdictAccept,
	}
}

func (v *verdictP) ofKind(kind nftExpr.VerdictKind, chain string) *verdictP {
	v.kind = kind
	v.chain = chain
	return v
}

func (v *verdictP) Accept() *verdictP {
	return v.ofKind(nftExpr.VerdictAccept, "")
}

func (v *verdictP) Drop() *verdictP {
	return v.ofKind(nftExpr.VerdictDrop, "")
}

func (v *verdictP) Return() *verdictP {
	return v.ofKind(nftExpr.VerdictReturn, "")
}

func (v *verdictP) Jump(chain string) *verdictP {
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
