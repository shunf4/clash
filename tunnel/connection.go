package tunnel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type packetSender struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan C.PacketAdapter

	// destination NAT mapping
	originToTarget map[string]netip.Addr
	targetToOrigin map[netip.Addr]netip.Addr
	mappingMutex   sync.RWMutex

	// mod: remote UDP resolution. Sessions whose destination stays a domain name
	// are resolved by the upstream server. Their replies may come from an address
	// the tunnel never saw, so remember the session destination and index reply
	// addresses to it, then write replies back with an address the local side
	// knows. A sender belongs to a single local socket, so there is one session.
	remoteSessions   map[netip.Addr]netip.Addr
	remotePorts      map[netip.Addr]uint16
	remoteOrigin     netip.Addr
	remoteOriginPort uint16
}

// newPacketSender return a chan based C.PacketSender
// It ensures that packets can be sent sequentially and without blocking
func newPacketSender() C.PacketSender {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan C.PacketAdapter, senderCapacity)
	return &packetSender{
		ctx:    ctx,
		cancel: cancel,
		ch:     ch,

		originToTarget: make(map[string]netip.Addr),
		targetToOrigin: make(map[netip.Addr]netip.Addr),
		remoteSessions: make(map[netip.Addr]netip.Addr),
		remotePorts:    make(map[netip.Addr]uint16),
	}
}

func (s *packetSender) AddMapping(originMetadata *C.Metadata, metadata *C.Metadata) {
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	originKey := originMetadata.String()
	originAddr := originMetadata.DstIP
	targetAddr := metadata.DstIP
	if addr := s.originToTarget[originKey]; !addr.IsValid() { // overwrite only if the record is illegal
		s.originToTarget[originKey] = targetAddr
	}
	if addr := s.targetToOrigin[targetAddr]; !addr.IsValid() { // overwrite only if the record is illegal
		s.targetToOrigin[targetAddr] = originAddr
	}
}

func (s *packetSender) RestoreReadFrom(addr netip.Addr) netip.Addr {
	s.mappingMutex.RLock()
	defer s.mappingMutex.RUnlock()
	if originAddr := s.targetToOrigin[addr]; originAddr.IsValid() {
		return originAddr
	}
	return addr
}

	// mod: remote UDP resolution. Remember the original destination of a session
	// that is sent with a domain name, keyed by the address the local side knows.
	// A plain domain destination usually carries no Fake-IP, so the key equals the
	// destination and reply restore is a no-op; the mapping exists for the case
	// where the local side uses a Fake-IP.
func (s *packetSender) addRemoteMapping(originAddr netip.Addr, port uint16) {
	if !originAddr.IsValid() {
		return
	}
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	originAddr = originAddr.Unmap()
	if _, exist := s.remoteSessions[originAddr]; !exist {
		s.remoteSessions[originAddr] = originAddr
		s.remotePorts[originAddr] = port
	}
	// A sender serves one local socket, so the destination of its domain session
	// is unique and is used as the fallback for unexpected reply addresses.
	if !s.remoteOrigin.IsValid() {
		s.remoteOrigin = originAddr
		s.remoteOriginPort = port
	}
}

// RemoteOrigin returns the destination of the domain session of this sender, if
// any. A sender belongs to a single local socket, so there is at most one.
//
// mod: remote UDP resolution.
func (s *packetSender) RemoteOrigin() (netip.Addr, uint16, bool) {
	s.mappingMutex.RLock()
	defer s.mappingMutex.RUnlock()
	return s.remoteOrigin, s.remoteOriginPort, s.remoteOrigin.IsValid()
}

// RecordReply indexes the reply address to the destination of the domain
// session, so replies can be written back with an address the local side knows.
//
// mod: remote UDP resolution.
func (s *packetSender) RecordReply(replyAddr netip.Addr) {
	replyAddr = replyAddr.Unmap()
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	if !s.remoteOrigin.IsValid() || !replyAddr.IsValid() {
		return
	}
	if _, exist := s.remoteSessions[replyAddr]; !exist {
		s.remoteSessions[replyAddr] = s.remoteOrigin
		s.remotePorts[replyAddr] = s.remoteOriginPort
	}
}

// RemoteSessionAddr is the fallback for replies coming from an address that was
// not seen before. The returned address is the destination the local side knows
// (with the reply's port); the bool is false for senders that never carried a
// domain session, whose replies follow the normal IP based path.
//
// mod: remote UDP resolution.
func (s *packetSender) RemoteSessionAddr(reply netip.AddrPort) (net.Addr, bool) {
	originAddr, _, ok := s.RemoteOrigin()
	if !ok {
		return nil, false
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(originAddr, reply.Port())), true
}

// isRemoteSession reports whether the sender carries a domain session.
//
// mod: remote UDP resolution.
func (s *packetSender) isRemoteSession() bool {
	_, _, ok := s.RemoteOrigin()
	return ok
}

// RemoteAddr reports the original destination of a remote UDP session whose
// destination stayed a domain name, so replies can be written back to the
// address the local side expects (possibly a Fake-IP) instead of the upstream
// server's view of it.
//
// mod: remote UDP resolution.
func (s *packetSender) RemoteAddr(addr netip.Addr) (net.Addr, bool) {
	addr = addr.Unmap()
	s.mappingMutex.RLock()
	originAddr, remote := s.remoteSessions[addr]
	port, portOk := s.remotePorts[addr]
	s.mappingMutex.RUnlock()
	if !remote || !portOk || !originAddr.IsValid() || originAddr == addr {
		return nil, false
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(originAddr, port)), true
}

func (s *packetSender) processPacket(pc C.PacketConn, packet C.PacketAdapter) {
	defer packet.Drop()
	metadata := packet.Metadata()

	var addr net.Addr

	s.mappingMutex.RLock()
	targetAddr := s.originToTarget[metadata.String()]
	s.mappingMutex.RUnlock()

	if targetAddr.IsValid() {
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(targetAddr, metadata.DstPort))
	}

	// mod: remote UDP resolution. Decided once per NAT session, from the session
	// target: the domain name is handed over so the upstream server resolves it
	// (socks5h semantics, no local DNS leak). The destination is remembered for
	// the replies (see RemoteAddr); when it is a Fake-IP the local side learns it
	// back, and a plain IP (the usual case for socks5h clients) needs no mapping.
	if addr == nil && supportRemoteUDP(pc) && metadata.Host != "" {
		s.addRemoteMapping(metadata.DstIP, metadata.DstPort)
		_ = handleUDPToRemote(packet, pc, remoteUDPAddr(metadata))
		return
	}

	if addr == nil {
		originMetadata := metadata  // save origin metadata
		metadata = metadata.Clone() // don't modify PacketAdapter's metadata

		_ = preHandleMetadata(metadata) // error was pre-checked
		metadata = metadata.Pure()
		if metadata.Host != "" {
			// TODO: ResolveUDP may take a long time to block the Process loop
			//       but we want keep sequence sending so can't open a new goroutine
			if err := pc.ResolveUDP(s.ctx, metadata); err != nil {
				log.Warnln("[UDP] Resolve Ip error: %s", err)
				return
			}
		}

		if !metadata.DstIP.IsValid() {
			log.Warnln("[UDP] Destination ip not valid: %#v", metadata)
			return
		}
		// mod: remote UDP resolution. The session target was resolved here, so it
		// is sent with a concrete address; replies are indexed back to it and the
		// domain session mapping (if any) never takes over.
		s.AddMapping(originMetadata, metadata)
		addr = metadata.UDPAddr()
	}
	_ = handleUDPToRemote(packet, pc, addr)
}

// remoteAddrRestorer is implemented by packet senders able to tell the original
// destination of a remote UDP session and to index replies to it (see
// packetSender.RemoteAddr and packetSender.RecordReply).
//
// mod: remote UDP resolution.
type remoteAddrRestorer interface {
	RemoteAddr(addr netip.Addr) (net.Addr, bool)
	RecordReply(replyAddr netip.Addr)
}

// remoteSessionRestorer is implemented by packet senders that record the
// destination of domain sessions; it is used as a fallback when a reply comes
// from an address that was not seen before (naive upstream servers) and to tell
// apart domain sessions from the normal IP based ones.
//
// mod: remote UDP resolution.
type remoteSessionRestorer interface {
	RemoteSessionAddr(reply netip.AddrPort) (net.Addr, bool)
	isRemoteSession() bool
}

// supportRemoteUDP reports whether the outbound can receive a domain name as
// the per-packet UDP destination.
func supportRemoteUDP(pc C.PacketConn) bool {
	resolver, ok := pc.(C.RemoteUDPResolver)
	return ok && resolver.SupportRemoteUDP()
}

// remoteUDPAddr returns the destination handed to an outbound that resolves
// domain names remotely.
//
// mod: remote UDP resolution.
func remoteUDPAddr(metadata *C.Metadata) net.Addr {
	return N.NewRemoteUDPAddr(metadata.Host, metadata.DstPort)
}

func (s *packetSender) Process(pc C.PacketConn, proxy C.WriteBackProxy) {
	for {
		select {
		case <-s.ctx.Done():
			return // sender closed
		case packet := <-s.ch:
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			s.processPacket(pc, packet)
		}
	}
}

func (s *packetSender) dropAll() {
	for {
		select {
		case data := <-s.ch:
			data.Drop() // drop all data still in chan
		default:
			return // no data, exit goroutine
		}
	}
}

func (s *packetSender) Send(packet C.PacketAdapter) {
	select {
	case <-s.ctx.Done():
		packet.Drop() // sender closed before Send()
		return
	default:
	}

	select {
	case s.ch <- packet:
		// put ok, so don't drop packet, will process by other side of chan
	case <-s.ctx.Done():
		packet.Drop() // sender closed when putting data to chan
	default:
		packet.Drop() // chan is full
	}
}

func (s *packetSender) Close() {
	s.cancel()
	s.dropAll()
}

func (s *packetSender) DoSniff(metadata *C.Metadata) error { return nil }

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, addr net.Addr) error {
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(writeBack C.WriteBack, pc C.PacketConn, sender C.PacketSender, key string, oAddrPort netip.AddrPort) {
	defer func() {
		sender.Close()
		_ = pc.Close()
		closeAllLocalCoon(key)
		natTable.Delete(key)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			return
		}

		fromUDPAddr, isUDPAddr := from.(*net.UDPAddr)
		if !isUDPAddr {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a [%T](%s) which isn't a *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", from, from, oAddrPort)
		} else if fromUDPAddr == nil {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a nil *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", oAddrPort)
		}

		fromAddrPort := fromUDPAddr.AddrPort()
		fromAddr := fromAddrPort.Addr().Unmap()

		// mod: remote UDP resolution. A session sent with a domain name was not
		// resolved locally, so its replies come from an address the local side never
		// saw. Record the reply address first (a naive server may answer from its own
		// view of the destination), then restore the local side's destination; the
		// fallback keeps replies deliverable when the server answers from an address
		// that was not expected.
		if restorer, ok := sender.(remoteAddrRestorer); ok {
			restorer.RecordReply(fromAddr)
			if remoteAddr, ok := restorer.RemoteAddr(fromAddr); ok {
				_, err = writeBack.WriteBack(data, remoteAddr)
				if put != nil {
					put()
				}
				if err != nil {
					return
				}
				continue
			}
		}
		if restorer, ok := sender.(remoteSessionRestorer); ok {
			if restorer.isRemoteSession() {
				if remoteAddr, ok := restorer.RemoteSessionAddr(fromAddrPort); ok {
					_, err = writeBack.WriteBack(data, remoteAddr)
					if put != nil {
						put()
					}
					if err != nil {
						return
					}
					continue
				}
				// This is a domain session but the reply address is unknown and
				// there is no fallback destination. Dropping the reply is safer
				// than guessing.
				if put != nil {
					put()
				}
				continue
			}
		}

		// restore DestinationNAT
		fromAddr = sender.RestoreReadFrom(fromAddr).Unmap()

		fromAddrPort = netip.AddrPortFrom(fromAddr, fromAddrPort.Port())

		_, err = writeBack.WriteBack(data, net.UDPAddrFromAddrPort(fromAddrPort))
		if put != nil {
			put()
		}
		if err != nil {
			return
		}
	}
}

func closeAllLocalCoon(lAddr string) {
	natTable.RangeForLocalConn(lAddr, func(key string, value *net.UDPConn) bool {
		conn := value

		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", lAddr, key)
		return true
	})
}

func handleSocket(inbound, outbound net.Conn) {
	N.Relay(inbound, outbound)
}
