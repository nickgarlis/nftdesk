package models

import (
	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// type TableFamily byte
type TableFamily = nftables.TableFamily

// Possible TableFamily values.
const (
	TableFamilyUnspecified TableFamily = unix.NFPROTO_UNSPEC
	TableFamilyINet        TableFamily = unix.NFPROTO_INET
	TableFamilyIPv4        TableFamily = unix.NFPROTO_IPV4
	TableFamilyIPv6        TableFamily = unix.NFPROTO_IPV6
	TableFamilyARP         TableFamily = unix.NFPROTO_ARP
	TableFamilyNetdev      TableFamily = unix.NFPROTO_NETDEV
	TableFamilyBridge      TableFamily = unix.NFPROTO_BRIDGE
)
