package outbound

import (
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

// mod: remote UDP resolution.
//
// Outbounds whose UDP wire format carries the destination address inside every
// packet (SOCKS5, Shadowsocks, SSR, Snell) can forward a domain name to the
// upstream server instead of resolving it locally (socks5h semantics). The
// capability is published through C.RemoteUDPResolver, and the tunnel then
// passes an *N.RemoteUDPAddr as destination to WriteTo.
//
// The wire encoders of SOCKS5/SSR/Snell (and Shadowsocks through
// M.SocksaddrFromNet) parse unknown net.Addr values from their textual form and
// emit ATYP_DOMAINNAME, so the address passes through. The wrappers below only
// publish the capability, because the tunnel sees the statistics wrapper
// returned by ListenPacketContext, not the adapters' internal packetConn.

type socksRemoteUDPPacketConn struct{ C.PacketConn }

func (c *socksRemoteUDPPacketConn) SupportRemoteUDP() bool { return true }

type ssrRemoteUDPPacketConn struct{ C.PacketConn }

func (c *ssrRemoteUDPPacketConn) SupportRemoteUDP() bool { return true }

type snellRemoteUDPPacketConn struct{ C.PacketConn }

func (c *snellRemoteUDPPacketConn) SupportRemoteUDP() bool { return true }

type ssRemoteUDPPacketConn struct{ C.PacketConn }

func (c *ssRemoteUDPPacketConn) SupportRemoteUDP() bool { return true }

// remoteUDPInitialTarget returns the textual destination to use at dial time,
// before the first packet arrives. A domain name is kept as a name so it is
// never resolved locally; a resolved IP is only used when there is no name.
func remoteUDPInitialTarget(metadata *C.Metadata) (host string, port uint16) {
	if metadata.Host != "" {
		return metadata.Host, metadata.DstPort
	}
	if metadata.DstIP.IsValid() {
		return metadata.DstIP.String(), metadata.DstPort
	}
	return "", metadata.DstPort
}

// remoteUDPBindAddr returns the destination used to bind a packet conn that
// encodes the destination once. When the metadata carries a domain name it is
// kept as text, otherwise the resolved UDP address is used.
func remoteUDPBindAddr(metadata *C.Metadata) net.Addr {
	if metadata.Host != "" {
		return &remoteUDPWriteAddr{host: metadata.Host, port: metadata.DstPort}
	}
	return metadata.UDPAddr()
}

// remoteUDPWriteAddr is the textual form of a destination used by code paths
// (for example the Shadowsocks bind address) that only understand net.Addr.
type remoteUDPWriteAddr struct {
	host string
	port uint16
}

func (a *remoteUDPWriteAddr) Network() string { return "udp" }

func (a *remoteUDPWriteAddr) String() string {
	return net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
}

// remoteAddrForWrite turns the tunnel's domain destination into the address
// form the Shadowsocks packet conn encodes.
func remoteAddrForWrite(addr net.Addr) net.Addr {
	remote, ok := addr.(*N.RemoteUDPAddr)
	if !ok {
		return addr
	}
	return &remoteUDPWriteAddr{host: remote.Host, port: remote.Port}
}

// remoteUDPNamePacketConn restores domain destinations for a packet conn whose
// bind wrapper would otherwise encode a resolved IP.
type remoteUDPNamePacketConn struct {
	N.EnhancePacketConn
}

func (c *remoteUDPNamePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.EnhancePacketConn.WriteTo(b, remoteAddrForWrite(addr))
}
