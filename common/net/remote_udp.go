package net

import (
	"net"
	"strconv"
)

// mod: remote UDP resolution. RemoteUDPAddr is a UDP destination that keeps the
// domain name instead of a resolved IP. Outbound packet conns whose wire format
// carries the destination in every packet (SOCKS5, Shadowsocks, SSR, Snell)
// receive it through net.Addr and forward the name, letting the upstream server
// resolve it. This avoids a local DNS query (and the associated DNS leak) in
// socks5h-like setups.
type RemoteUDPAddr struct {
	Host string
	Port uint16
}

func (a *RemoteUDPAddr) Network() string { return "udp" }

func (a *RemoteUDPAddr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}

// NewRemoteUDPAddr returns a UDP destination address that carries a hostname.
func NewRemoteUDPAddr(host string, port uint16) *RemoteUDPAddr {
	return &RemoteUDPAddr{Host: host, Port: port}
}
