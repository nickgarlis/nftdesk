package models

import (
	"fmt"

	"github.com/google/nftables"
)

func NewRule(conn *nftables.Conn, obj *nftables.Rule) *Rule {
	return &Rule{conn: conn, obj: obj}
}

type Rule struct {
	conn *nftables.Conn
	obj  *nftables.Rule
}

func (r *Rule) Handle() uint64 {
	return r.obj.Handle
}

func (r *Rule) Delete() error {
	if err := r.conn.DelRule(r.obj); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}
	return nil
}
