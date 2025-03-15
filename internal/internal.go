package internal

import (
	"encoding/binary"
	"net"

	"github.com/seancfoley/ipaddress-go/ipaddr"
)

func NetIPToBytes(ip net.IP) []byte {
	if ip.To4() != nil {
		return []byte(ip.To4())
	} else {
		return []byte(ip.To16())
	}
}

func PortToBytes(port uint16) []byte {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	return portBytes
}

// Not exactly the same as the actual subnet range but this is what
// nftables expects for intervals
func GetSubnetRange(ip *ipaddr.IPAddress) (net.IP, net.IP) {
	subnet := ip.ToPrefixBlock()
	networkIp := subnet.GetLower().GetNetIP()
	nextNetworkIp := subnet.GetUpper().Increment(1).GetNetIP()
	return networkIp, nextNetworkIp
}
