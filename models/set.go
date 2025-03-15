package models

import (
	"time"

	"github.com/google/nftables"
)

type IPAddrSetElement struct {
	IP      string
	Timeout time.Duration
	Comment string
}

type PortSetElement struct {
	Port    uint16
	Timeout time.Duration
	Comment string
}

func NewSet(conn *nftables.Conn, obj *nftables.Set) *Set {
	return &Set{conn: conn, obj: obj}
}

type Set struct {
	conn *nftables.Conn
	obj  *nftables.Set
}

func (s *Set) ID() uint32 {
	return s.obj.ID
}

func (s *Set) Name() string {
	return s.obj.Name
}

func (s *Set) Comment() string {
	return s.obj.Comment
}

func (s *Set) Anonymous() bool {
	return s.obj.Anonymous
}

func (s *Set) Constant() bool {
	return s.obj.Constant
}

func (s *Set) Flush() {
	s.conn.FlushSet(s.obj)
}

func (s *Set) Delete() {
	s.conn.DelSet(s.obj)
}
