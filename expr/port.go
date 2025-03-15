package expr

import (
	"encoding/binary"

	nftExpr "github.com/google/nftables/expr"
)

type PortP struct {
	offset Offset
}

func PortPayload() *PortP {
	return &PortP{
		offset: OffsetSourcePort,
	}
}

func (p *PortP) OfKindSource() *PortP {
	p.offset = OffsetSourcePort
	return p
}

func (p *PortP) OfKindDest() *PortP {
	p.offset = OffsetDestPort
	return p
}

func (p *PortP) ToNftExprs() []nftExpr.Any {
	return []nftExpr.Any{
		&nftExpr.Payload{
			DestRegister: 1,
			Base:         nftExpr.PayloadBaseTransportHeader,
			Offset:       uint32(p.offset),
			Len:          2,
		},
	}
}

func (p *PortP) Eq(port uint16) *CmpExpression {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	return newCompExpression(p, nftExpr.CmpOpEq, portBytes)
}

func (p *PortP) Neq(port uint16) *CmpExpression {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	return newCompExpression(p, nftExpr.CmpOpNeq, portBytes)
}

func (p *PortP) InSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(p, id, name, false)
}

func (p *PortP) NotInSet(id uint32, name string) *LookupExpression {
	return newLookupExpression(p, id, name, true)
}

func (i *PortP) InAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", false)
}

func (i *PortP) NotInAnonSet(id uint32) *LookupExpression {
	return newLookupExpression(i, id, "", true)
}
