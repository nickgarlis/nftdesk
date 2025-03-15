package models

import (
	"fmt"

	"github.com/nickgarlis/nftdesk/expr"

	"github.com/google/nftables"
	nftExpr "github.com/google/nftables/expr"
)

func NewChain(conn *nftables.Conn, obj *nftables.Chain) *Chain {
	return &Chain{conn: conn, obj: obj}
}

type Chain struct {
	conn *nftables.Conn
	obj  *nftables.Chain
}

func (c *Chain) Name() string {
	return c.obj.Name
}

func (c *Chain) Flush() {
	c.conn.FlushChain(c.obj)
}

func (c *Chain) Delete() {
	c.conn.DelChain(c.obj)
}

func (c *Chain) HasRule(handle uint64) bool {
	rules, _ := c.conn.GetRules(c.obj.Table, c.obj)

	for _, rule := range rules {
		if rule.Handle == handle {
			return true
		}
	}

	return false
}

func (c *Chain) DeleteRule(handle uint64) error {
	rule := &nftables.Rule{
		Table:  c.obj.Table,
		Chain:  c.obj,
		Handle: handle,
	}
	if err := c.conn.DelRule(rule); err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	return nil
}

func (c *Chain) ListRules() ([]*Rule, error) {
	rules, err := c.conn.GetRules(c.obj.Table, c.obj)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}

	var result []*Rule
	for _, rule := range rules {
		result = append(result, &Rule{conn: c.conn, obj: rule})
	}

	return result, nil
}

func (c *Chain) AddRule(exs ...expr.Expression) (*Rule, error) {
	var exprs []nftExpr.Any
	for _, ex := range exs {
		exprs = append(exprs, ex.ToNftExprs()...)
	}
	rule := &nftables.Rule{
		Table: c.obj.Table,
		Chain: c.obj,
		Exprs: exprs,
	}

	rule = c.conn.AddRule(rule)

	return NewRule(c.conn, rule), nil
}
