package models

import (
	"fmt"

	"github.com/nickgarlis/nftdesk/internal"

	"github.com/google/nftables"
	"github.com/seancfoley/ipaddress-go/ipaddr"
)

func NewTable(conn *nftables.Conn, obj *nftables.Table) *Table {
	return &Table{conn: conn, obj: obj}
}

type Table struct {
	conn *nftables.Conn
	obj  *nftables.Table
}

func (t *Table) Name() string {
	return t.obj.Name
}

func (t *Table) Family() nftables.TableFamily {
	return t.obj.Family
}

func (t *Table) Flush() {
	t.conn.FlushTable(t.obj)
}

func (t *Table) Delete() {
	t.conn.DelTable(t.obj)
}

func (t *Table) HasChain(name string) bool {
	chain, _ := t.conn.ListChain(t.obj, name)
	return chain != nil
}

func (t *Table) ListChain(name string) (*Chain, error) {
	chain, err := t.conn.ListChain(t.obj, name)
	if err != nil {
		return nil, err
	}

	return &Chain{conn: t.conn, obj: chain}, nil
}

func (t *Table) ListChains() ([]*Chain, error) {
	chains, err := t.conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("failed to list chains: %w", err)
	}

	var result []*Chain
	for _, chain := range chains {
		if chain.Table.Name == t.obj.Name && chain.Table.Family == t.obj.Family {
			result = append(result, &Chain{conn: t.conn, obj: chain})
		}
	}

	return result, nil
}

func (t *Table) AddChain(name string) *Chain {
	chainObj := t.conn.AddChain(&nftables.Chain{
		Name:  name,
		Table: t.obj,
	})

	return NewChain(t.conn, chainObj)
}

func (t *Table) getSets() ([]*nftables.Set, error) {
	sets, err := t.conn.GetSets(t.obj)
	if err != nil {
		return nil, fmt.Errorf("failed to get sets: %w", err)
	}

	return sets, nil
}

func (t *Table) GetNamedSets() ([]*Set, error) {
	sets, err := t.getSets()
	if err != nil {
		return nil, err
	}

	var res []*Set
	for _, s := range sets {
		if !s.Anonymous {
			res = append(res, &Set{conn: t.conn, obj: s})
		}
	}

	return res, nil
}

func (t *Table) GetNamedSet(name string) (*Set, error) {
	set, err := t.conn.GetSetByName(t.obj, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get set: %w", err)
	}

	return NewSet(t.conn, set), nil
}

func (t *Table) AddAnonIPAddrSet(elements []*IPAddrSetElement) (*Set, error) {
	return t.AddIPAddrSet("", elements)
}

func (t *Table) AddIPAddrSet(name string, elements []*IPAddrSetElement) (*Set, error) {
	setObj := &nftables.Set{
		Constant:  name == "",
		Anonymous: name == "",
		Name:      name,
		KeyType:   nftables.TypeIPAddr,
		Table:     t.obj,
	}
	var setElements []nftables.SetElement
	for _, e := range elements {
		if e.Timeout > 0 {
			setObj.HasTimeout = true
		}
		addr, err := ipaddr.NewIPAddressString(e.IP).ToAddress()
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP address: %w", err)
		}
		if addr.IsIPv6() {
			return nil, fmt.Errorf("use AddIP6AddrSet for IPv6 addresses")
		}

		if addr.IsPrefixed() {
			setObj.Interval = true
			networkIp, nextNetworkIp := internal.GetSubnetRange(addr)
			setElements = append(setElements,
				nftables.SetElement{
					Key:         internal.NetIPToBytes(networkIp),
					IntervalEnd: false,
					Timeout:     e.Timeout,
					Comment:     e.Comment,
				},
				nftables.SetElement{
					Key:         internal.NetIPToBytes(nextNetworkIp),
					IntervalEnd: true,
				},
			)
		} else {
			setElements = append(setElements, nftables.SetElement{
				Key:     internal.NetIPToBytes(addr.GetNetIP()),
				Timeout: e.Timeout,
				Comment: e.Comment,
			})
		}
	}

	err := t.conn.AddSet(setObj, setElements)
	if err != nil {
		return nil, fmt.Errorf("failed to add set: %w", err)
	}

	return NewSet(t.conn, setObj), nil
}

func (t *Table) AddIP6AddrSet(name string, elements []*IPAddrSetElement) (*Set, error) {
	setObj := &nftables.Set{
		Constant:  name == "",
		Anonymous: name == "",
		Name:      name,
		KeyType:   nftables.TypeIP6Addr,
		Table:     t.obj,
	}
	var setElements []nftables.SetElement
	for _, e := range elements {
		if e.Timeout > 0 {
			setObj.HasTimeout = true
		}
		addr, err := ipaddr.NewIPAddressString(e.IP).ToAddress()
		if err != nil {
			return nil, fmt.Errorf("failed to parse IP address: %w", err)
		}
		if addr.IsIPv4() {
			return nil, fmt.Errorf("use AddIPAddrSet for IPv4 addresses")
		}

		if addr.IsPrefixed() {
			setObj.Interval = true
			networkIp, nextNetworkIp := internal.GetSubnetRange(addr)
			setElements = append(setElements,
				nftables.SetElement{
					Key:         internal.NetIPToBytes(networkIp),
					IntervalEnd: false,
					Timeout:     e.Timeout,
					Comment:     e.Comment,
				},
				nftables.SetElement{
					Key:         internal.NetIPToBytes(nextNetworkIp),
					IntervalEnd: true,
				},
			)
		} else {
			setElements = append(setElements, nftables.SetElement{
				Key:     internal.NetIPToBytes(addr.GetNetIP()),
				Timeout: e.Timeout,
				Comment: e.Comment,
			})
		}
	}

	err := t.conn.AddSet(setObj, setElements)
	if err != nil {
		return nil, fmt.Errorf("failed to add set: %w", err)
	}

	return NewSet(t.conn, setObj), nil
}

func (t *Table) AddPortSet(name string, elements []*PortSetElement) (*Set, error) {
	setObj := &nftables.Set{
		Constant:  name == "",
		Anonymous: name == "",
		Name:      name,
		KeyType:   nftables.TypeInetService,
		Table:     t.obj,
	}
	var setElements []nftables.SetElement
	for _, e := range elements {
		if e.Timeout > 0 {
			setObj.HasTimeout = true
		}
		setElements = append(setElements, nftables.SetElement{
			Key:     internal.PortToBytes(e.Port),
			Timeout: e.Timeout,
			Comment: e.Comment,
		})
	}

	err := t.conn.AddSet(setObj, setElements)
	if err != nil {
		return nil, fmt.Errorf("failed to add set: %w", err)
	}

	return NewSet(t.conn, setObj), nil
}

func (t *Table) AddAnonPortSet(elements []*PortSetElement) (*Set, error) {
	return t.AddPortSet("", elements)
}
