package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/pkg/errors"
)

var (
	reverseCtx       context.Context
	reverseCtxCancel context.CancelFunc
	reverseMux       sync.Mutex
)

func RestartReverse(firstStart bool) {
	reverseMux.Lock()
	defer reverseMux.Unlock()

	if reverseCtxCancel != nil {
		reverseCtxCancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	reverseCtx = ctx
	reverseCtxCancel = cancel

	go func() {
		if firstStart {
			time.Sleep(1 * time.Second)
		}
		log.Debugln("(re)start reverse machanism")

		address := "localhost:38684"

		metadata := &C.Metadata{}
		metadata.NetWork = C.TCP
		metadata.Type = C.INNER
		metadata.DNSMode = C.DNSNormal
		metadata.Process = C.MihomoName
		metadata.SpecialProxy = "Localhost-Mitm-Relay"

		if h, port, err := net.SplitHostPort(address); err == nil {
			if port, err := strconv.ParseUint(port, 10, 16); err == nil {
				metadata.DstPort = uint16(port)
			}
			if ip, err := netip.ParseAddr(h); err == nil {
				metadata.DstIP = ip
			} else {
				metadata.Host = h
			}
		}

		for {
			conn1, conn2 := net.Pipe()

			go func() {
				log.Debugln("starts reverse bridge connection")
				Tunnel.HandleTCPConn(conn2, metadata)
				log.Debugln("ends reverse bridge connection")
			}()

			// conn1 is a V2Ray Mux Server Worker connection.
			_ = conn1
			sessions := map[uint16]int

			for {
				select {
				case <-ctx.Done():
					conn1.Close()
					return
				default:
					f, err := muxServerHandleFrame(conn1)
					if err != nil {
						if errors.Cause(err) == io.EOF {
							log.Warnln("reverse: unexpected EOF in bridge connection, aborting")
						}
						conn1.Close()
						return
					}

				}
			}

		}
	}()
}

type MuxSession struct {
	downstreamWriter io.Writer
}

type MuxServerWorker struct {
	sync.RWMutex
	sessions map[uint16]*MuxSession
}

type FrameMetadata struct {
	SessionID     uint16
	Option        byte
	SessionStatus SessionStatus
	NetType       byte
	TargetIP      net.IP
	TargetDomain  string
	TargetPort    uint16
}

type SessionStatus = byte

const (
	SessionStatusNew       SessionStatus = 0x01
	SessionStatusKeep      SessionStatus = 0x02
	SessionStatusEnd       SessionStatus = 0x03
	SessionStatusKeepAlive SessionStatus = 0x04
)

const (
	OptionNone  = byte(0x00)
	OptionData  = byte(0x01)
	OptionError = byte(0x02)
)

func muxServerGetSession(w *MuxServerWorker, sessionID uint16) (*MuxSession, bool) {
	w.RLock()
	defer w.RUnlock()

	result, found := w.sessions[sessionID]
	return result, found
}

func muxUtilDiscardData(conn net.Conn) error {
	dataLenRaw := [2]byte{}
	_, err := conn.Read(dataLenRaw[:])
	if err != nil {
		log.Errorln("muxUtilDiscardData: reading frame data len: %v", err)
		return err
	}
	dataLen := int(binary.BigEndian.Uint16(dataLenRaw[:]))
	_, err = io.CopyN(io.Discard, conn, int64(dataLen))
	if err != nil {
		log.Errorln("muxUtilDiscardData: reading frame data body: %v", err)
		return err
	}
	return nil
}

func muxServerHandleFrame(w *MuxServerWorker, conn net.Conn) (*FrameMetadata, error) {
	f, err := muxServerReadFrame(conn)
	if err != nil {
		log.Errorln("muxServerHandleFrame: error in muxServerReadFrame: %v", err)
		return nil, err
	}

	switch f.SessionStatus {
	case SessionStatusKeepAlive:
		// Do nothing than drain data
		if (f.Option & OptionError) != 0 {
			log.Warnln("muxServerHandleFrame: received frame.Option has OptionError, aborting")
			return nil, fmt.Errorf("frame has OptionError")
		}
		if (f.Option & OptionData) != 0 {
			err := muxUtilDiscardData(conn)
			if err != nil {
				log.Errorln("muxServerHandleFrame: error when discarding data: %v", err)
				return nil, err
			}
		}
	case SessionStatusKeep:
		if (f.Option & OptionError) != 0 {
			log.Warnln("muxServerHandleFrame: received frame.Option has OptionError, aborting")
			return nil, fmt.Errorf("frame has OptionError")
		}
		if (f.Option & OptionData) == 0 {
			return f, nil
		}
		s, found := muxServerGetSession(w, f.SessionID)
		if !found {
			// Notify remote peer to close this session.
			responseBuf := [6]byte{}
			binary.BigEndian.PutUint16(responseBuf[0:2], uint16(4))
			binary.BigEndian.PutUint16(responseBuf[2:4], f.SessionID)
			responseBuf[4] = SessionStatusEnd
			responseBuf[5] = 0x00 // Option
			// net.Pipe() has internal lock
			_, err := conn.Write(responseBuf[:])
			if err != nil {
				return nil, err
			}

			err = muxUtilDiscardData(conn)
			if err != nil {
				log.Errorln("muxServerHandleFrame: error when discarding data: %v", err)
				return nil, err
			}
			return f, nil
		}

		dataLenRaw := [2]byte{}
		_, err := conn.Read(dataLenRaw[:])
		if err != nil {
			log.Errorln("xxx: reading frame data len: %v", err)
			return nil, err
		}
		dataLen := int(binary.BigEndian.Uint16(dataLenRaw[:]))
		data := make([]byte, dataLen)
		_, err = conn.Read(data)
		if err != nil {
			log.Errorln("xxx: reading frame data body: %v", err)
			return nil, err
		}
		_, err = s.downstreamWriter.Write(data)
		if err != nil {
			log.Errorln("xxx: writing frame data body to downstream: %v", err)

			// Notify remote peer to close this session.
			responseBuf := [6]byte{}
			binary.BigEndian.PutUint16(responseBuf[0:2], uint16(4))
			binary.BigEndian.PutUint16(responseBuf[2:4], f.SessionID)
			responseBuf[4] = SessionStatusEnd
			responseBuf[5] = 0x00 // Option
			// net.Pipe() has internal lock
			_, err := conn.Write(responseBuf[:])
			if err != nil {
				return nil, err
			}
		}
	}
}

func muxServerReadFrame(conn net.Conn) (*FrameMetadata, error) {
	metaLenRaw := [2]byte{}
	_, err := io.ReadFull(conn, metaLenRaw[:])
	if err != nil {
		log.Errorln("muxServerReadFrame: reading meta len: %v", err)
		return nil, err
	}
	metaLen := binary.BigEndian.Uint16(metaLenRaw[:])
	if metaLen > 512 {
		return nil, fmt.Errorf("invalid metalen %d", metaLen)
	}

	metaBuf := make([]byte, metaLen)

	if _, err := io.ReadFull(conn, metaBuf); err != nil {
		log.Errorln("muxServerReadFrame: reading meta buf: %v", err)
		return nil, err
	}

	return muxServerUnmarshalFromBuffer(metaBuf)
}

func muxServerUnmarshalFromBuffer(b []byte) (*FrameMetadata, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("insufficient buffer: %d", len(b))
	}

	f := FrameMetadata{}

	f.SessionID = binary.BigEndian.Uint16(b[0:2])
	f.SessionStatus = SessionStatus(b[2])
	f.Option = b[3]
	f.NetType = 0 // Unknown

	if f.SessionStatus == SessionStatusNew {
		if len(b) < 8 {
			return nil, fmt.Errorf("insufficient buffer: %d", len(b))
		}
		f.NetType = b[4]
		f.TargetPort = binary.BigEndian.Uint16(b[5:7])
		addrFamily := b[7]
		switch addrFamily {
		case 0x00: // net.AddressFamilyIPv4
			if len(b) < (8 + net.IPv4len) {
				return nil, fmt.Errorf("insufficient buffer for ipv4: %d", len(b))
			}
			f.TargetIP = net.IP(b[8 : 8+net.IPv4len])
		case 0x01: // net.AddressFamilyIPv6
			if len(b) < (8 + net.IPv6len) {
				return nil, fmt.Errorf("insufficient buffer for ipv6: %d", len(b))
			}
			f.TargetIP = net.IP(b[8 : 8+net.IPv6len])
		case 0x02: // net.AddressFamilyDomain
			if len(b) < (8 + 1) {
				return nil, fmt.Errorf("insufficient buffer for domain name host: %d", len(b))
			}
			domainLength := int(b[8])
			if len(b) < (8 + 1 + domainLength) {
				return nil, fmt.Errorf("insufficient buffer for domain name host: %d", len(b))
			}
			f.TargetDomain = string(b[9 : 9+domainLength])
		default:
			return nil, fmt.Errorf("invalid addrFamily byte: %d", addrFamily)
		}
	}

	return &f, nil
}
