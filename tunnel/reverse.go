package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"errors"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var (
	reverseCtx        context.Context
	reverseCtxCancel  context.CancelFunc
	reverseMutex      sync.Mutex
	reverseFirstStart bool = true

	lastCfgList                          []ReverseConf
	lastStopAfterErrRetryCount           int
	lastSeeAsErrorIfDisconnectInMillisec int
	lastEnableOnAndroidTypeTransports    []int
	lastCurrAndroidTypeTransports        int = -2
)

type ClashrayReverseContact struct {
	ReverseIdentDomain string `yaml:"reverse-ident-domain"`
	BridgeConnProxy    string `yaml:"bridge-conn-proxy"`
	VisitorProxy       string `yaml:"visitor-proxy"`
	// WorkerNum currently is not used.
	WorkerNum          int `yaml:"worker-num"`
	RetryDelayMillisec int `yaml:"retry-delay-millisec"`
}

type ClashrayNetPublisher struct {
	Name                              string                   `yaml:"name"`
	ContactProxyGroupFallbackIsLazy   bool                     `yaml:"contact-proxy-group-fallback-is-lazy"`
	ContactProxyGroupFallbackInterval int                      `yaml:"contact-proxy-group-fallback-interval"`
	ContactHealthcheckURL             string                   `yaml:"contact-healthcheck-url"`
	ContactSendURL                    string                   `yaml:"contact-send-url"`
	LanContactsCommonFields           map[string]interface{}   `yaml:"lan-contacts-common-fields"`
	LanContacts                       []map[string]interface{} `yaml:"lan-contacts"`
	ReverseContacts                   []ClashrayReverseContact `yaml:"reverse-contacts"`
	Services                          []string                 `yaml:"services"`
}

type Clashray struct {
	ClashrayNetCurrAsPublisher                  string                 `yaml:"clashray-net-curr-as-publisher"`
	ClashrayNetCurrIsAsVisitor                  bool                   `yaml:"clashray-net-curr-is-as-visitor"`
	ClashrayNetVisitorTunnelNoHostsNorListening bool                   `yaml:"clashray-net-visitor-tunnel-no-hosts-nor-listening"`
	ClashraySendDir                             string                 `yaml:"clashray-send-dir"`
	ClashraySendHistoryMaxSize                  uint32                 `yaml:"clashray-send-history-max-size"`
	ClashrayNetPublishers                       []ClashrayNetPublisher `yaml:"clashray-net-publishers"`
	ClashrayNetPublishersMap                    map[string]*ClashrayNetPublisher
	ClashrayHTTPRedirectMap                     map[string]string
	ClashraySendCORSAllowedOrigins              []string

	ClashrayNetHTTPRedirectLocalListenAddr string `yaml:"clashray-net-http-redirect-local-listen-addr"`
	ClashrayNetHTTPRedirectLocalListenPort uint16 `yaml:"clashray-net-http-redirect-local-listen-port-yes-i-dont-want-80"`
	ClashrayTestLocalListenAddr            string `yaml:"clashray-test-local-listen-addr"`
	ClashrayTestLocalListenPort            uint16 `yaml:"clashray-test-local-listen-port-yes-i-dont-want-80"`
	ClashraySendLocalListenAddr            string `yaml:"clashray-send-local-listen-addr"`
	ClashraySendLocalListenPort            uint16 `yaml:"clashray-send-local-listen-port-yes-i-dont-want-80"`
}

type ReverseConf struct {
	ReverseIdentDomain string `yaml:"reverse-ident-domain"`
	BridgeConnSubRule  string `yaml:"bridge-conn-sub-rule"`
	PayloadConnSubRule string `yaml:"payload-conn-sub-rule"`
	// WorkerNum currently is not used.
	WorkerNum          int `yaml:"worker-num"`
	RetryDelayMillisec int `yaml:"retry-delay-millisec"`
}

func saveReverseConfData(cfgList []ReverseConf, stopAfterErrRetryCount int, seeAsErrorIfDisconnectInMillisec int, enableOnAndroidTypeTransports []int, currAndroidTypeTransports int) {
	reverseMutex.Lock()
	defer reverseMutex.Unlock()

	lastCfgList = cfgList
	lastStopAfterErrRetryCount = stopAfterErrRetryCount
	lastSeeAsErrorIfDisconnectInMillisec = seeAsErrorIfDisconnectInMillisec
	lastEnableOnAndroidTypeTransports = enableOnAndroidTypeTransports
	if currAndroidTypeTransports != -2 {
		lastCurrAndroidTypeTransports = currAndroidTypeTransports
	}
}

func RestartReverseLast(currAndroidTypeTransports int) {
	RestartReverse(lastCfgList, lastStopAfterErrRetryCount, lastSeeAsErrorIfDisconnectInMillisec, lastEnableOnAndroidTypeTransports, currAndroidTypeTransports)
}

func RestartReverse(cfgList []ReverseConf, stopAfterErrRetryCount int, seeAsErrorIfDisconnectInMillisec int, enableOnAndroidTypeTransports []int, currAndroidTypeTransports int) {
	saveReverseConfData(cfgList, stopAfterErrRetryCount, seeAsErrorIfDisconnectInMillisec, enableOnAndroidTypeTransports, currAndroidTypeTransports)

	reverseMutex.Lock()
	defer reverseMutex.Unlock()

	if reverseCtxCancel != nil {
		reverseCtxCancel()
		reverseCtx = nil
		reverseCtxCancel = nil
	}

	if seeAsErrorIfDisconnectInMillisec <= 0 {
		seeAsErrorIfDisconnectInMillisec = 10000
	}

	log.Infoln("reverse: enableOnAndroidTypeTransports: %v, currAndroidTypeTransports: %d (last=%d)", enableOnAndroidTypeTransports, currAndroidTypeTransports, lastCurrAndroidTypeTransports)

	if len(enableOnAndroidTypeTransports) != 0 && lastCurrAndroidTypeTransports != -2 && !slices.Contains(enableOnAndroidTypeTransports, lastCurrAndroidTypeTransports) {
		log.Warnln("reverse: lastCurrAndroidTypeTransports not in allow list, not starting reverse")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	reverseCtx = ctx
	reverseCtxCancel = cancel

	shouldDelay := false
	log.Infoln("(re)start reverse mechanism")
	if reverseFirstStart {
		shouldDelay = true
		log.Infoln("wait for 1 second before starting reverse mechanism...")
		reverseFirstStart = false
	}

	for _, cfg := range cfgList {
		reverseIdentDomain := ""
		reverseIdentIP, err := netip.ParseAddr(cfg.ReverseIdentDomain)
		if err == nil {
			reverseIdentIP = netip.Addr{}
		} else {
			reverseIdentDomain = cfg.ReverseIdentDomain
		}

		thisCfg := cfg

		var delayTimerWhenStartingReverse *time.Timer
		if shouldDelay {
			delayTimerWhenStartingReverse = time.NewTimer(1 * time.Second)
		}

		go func() {
			if delayTimerWhenStartingReverse != nil {
				// Delay 1s before start
				select {
				case <-ctx.Done():
					// Cancelled
					delayTimerWhenStartingReverse.Stop()
					return
				case <-delayTimerWhenStartingReverse.C:
				}
			}

			metadata := &C.Metadata{}
			metadata.NetWork = C.TCP
			metadata.Type = C.TUNNEL
			metadata.DNSMode = C.DNSNormal
			metadata.Process = C.MihomoName

			metadata.DstPort = uint16(0)
			if reverseIdentIP.IsValid() {
				metadata.DstIP = reverseIdentIP
			} else {
				metadata.Host = reverseIdentDomain
			}

			metadata.SpecialRules = thisCfg.BridgeConnSubRule

			isRetrying := false
			lastStartTime := time.Now()
			errRetryCount := 0
		reverseRetry:
			for {
				if isRetrying {
					if stopAfterErrRetryCount > 0 && errRetryCount >= stopAfterErrRetryCount {
						log.Warnln("reverse: reverseIdentDomain=%s: error retry count reached %d, not retrying anymore", reverseIdentDomain, errRetryCount)
						break reverseRetry
					}
					if time.Since(lastStartTime) <= (time.Duration(seeAsErrorIfDisconnectInMillisec) * time.Millisecond) {
						errRetryCount += 1
						log.Infoln("reverse: reverseIdentDomain=%s: error connecting, retrying a %d time", reverseIdentDomain, errRetryCount)
					} else {
						errRetryCount = 0
					}
					log.Infoln("reverse: wait for %d milliseconds before retrying reverse connection...", thisCfg.RetryDelayMillisec)

					t := time.NewTimer(time.Duration(thisCfg.RetryDelayMillisec) * time.Millisecond)
					select {
					case <-ctx.Done():
						t.Stop()
						// Cancelled
						return
					case <-t.C:
					}
				} else {
					isRetrying = true
				}

				conn1, conn2 := net.Pipe()
				lastStartTime = time.Now()

				// conn1 is a V2Ray Mux Server Worker connection.
				w := &MuxServerWorker{
					fromBridgeWithRule: thisCfg.BridgeConnSubRule,
					sessions:           make(map[uint16]*MuxSession, 16),
					PayloadConnSubRule: thisCfg.PayloadConnSubRule,
				}

				go func() {
					log.Debugln("reverse: new MuxServerWorker %p: reverseIdentDomain=%s, reverseIdentIP=%s, bridgeConnSubRule=%s, payloadConnSubRule=%s: starts reverse bridge connection", w, reverseIdentDomain, reverseIdentIP.String(), thisCfg.BridgeConnSubRule, thisCfg.PayloadConnSubRule)
					Tunnel.HandleTCPConn(conn2, metadata)
					log.Debugln("reverse: new MuxServerWorker %p: reverseIdentDomain=%s, reverseIdentIP=%s, bridgeConnSubRule=%s, payloadConnSubRule=%s: ends reverse bridge connection", w, reverseIdentDomain, reverseIdentIP.String(), thisCfg.BridgeConnSubRule, thisCfg.PayloadConnSubRule)
				}()

				for {
					select {
					case <-ctx.Done():
						log.Debugln("reverse: MuxServerWorker %p: got ctx.Done()", w)
						conn1.Close()
						break reverseRetry
					default:
						_, err := muxServerHandleFrame(w, conn1)
						if err != nil {
							if errors.Is(err, io.EOF) {
								log.Warnln("reverse: MuxServerWorker %p: unexpected EOF in bridge connection, aborting", w)
							} else {
								log.Warnln("reverse: MuxServerWorker %p: when handling frame: %v", w, err)
							}
							conn1.Close()
							continue reverseRetry
						}

					}
				}
			}
		}()
	}

}

type MuxSession struct {
	downstreamWriter io.Writer
}

type MuxServerWorker struct {
	sync.RWMutex
	fromBridgeWithRule string
	sessions           map[uint16]*MuxSession
	PayloadConnSubRule string
}

type FrameMetadata struct {
	SessionID     uint16
	Option        byte
	SessionStatus SessionStatus
	NetType       byte
	TargetIP      netip.Addr
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

func muxServerAddSession(w *MuxServerWorker, sessionID uint16, session *MuxSession) {
	w.RLock()
	defer w.RUnlock()

	w.sessions[sessionID] = session
}

func muxServerGetSession(w *MuxServerWorker, sessionID uint16) (*MuxSession, bool) {
	w.RLock()
	defer w.RUnlock()

	result, found := w.sessions[sessionID]
	if found {
		// log.Debugln("get session %d", sessionID)
	} else {
		log.Debugln("warn: not found session %d", sessionID)
	}
	return result, found
}

func muxServerCloseSession(w *MuxServerWorker, sessionID uint16, s *MuxSession) error {
	w.RLock()
	defer w.RUnlock()

	delete(w.sessions, sessionID)

	if c, ok := s.downstreamWriter.(io.Closer); ok {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}

func muxUtilDiscardData(conn net.Conn) error {
	dataLenRaw := [2]byte{}
	_, err := io.ReadFull(conn, dataLenRaw[:])
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
		log.Debugln("server worker %p handling SessionStatusKeepAlive", w)
		// Do nothing than drain data
		if (f.Option & OptionData) != 0 {
			err := muxUtilDiscardData(conn)
			if err != nil {
				log.Errorln("muxServerHandleFrame: error when discarding data: %v", err)
				return nil, err
			}
		}
		return f, nil
	case SessionStatusKeep:
		// log.Debugln("server worker %p handling SessionStatusKeep", w)
		if (f.Option & OptionData) == 0 {
			return f, nil
		}
		s, found := muxServerGetSession(w, f.SessionID)
		if !found {
			log.Warnln("server worker %p: session %d not found; notify remote side to end this session", w, f.SessionID)
			// Notify remote peer to close this session.
			responseBuf := [6]byte{}
			binary.BigEndian.PutUint16(responseBuf[0:2], uint16(4))
			binary.BigEndian.PutUint16(responseBuf[2:4], f.SessionID)
			responseBuf[4] = SessionStatusEnd
			responseBuf[5] = byte(0x00) // Option
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
		_, err := io.ReadFull(conn, dataLenRaw[:])
		if err != nil {
			log.Errorln("muxServerHandleFrame: reading frame data len: %v", err)
			return nil, err
		}
		dataLen := int(binary.BigEndian.Uint16(dataLenRaw[:]))
		data := make([]byte, dataLen)
		_, err = io.ReadFull(conn, data)
		if err != nil {
			log.Errorln("muxServerHandleFrame: reading frame data body: %v", err)
			return nil, err
		}
		_, err = s.downstreamWriter.Write(data)
		if err != nil {
			log.Errorln("muxServerHandleFrame: writing frame data body to downstream: %v", err)

			// Notify remote peer to close this session.
			responseBuf := [6]byte{}
			binary.BigEndian.PutUint16(responseBuf[0:2], uint16(4))
			binary.BigEndian.PutUint16(responseBuf[2:4], f.SessionID)
			responseBuf[4] = SessionStatusEnd
			responseBuf[5] = byte(0x00) // Option
			// net.Pipe() has internal lock
			_, err := conn.Write(responseBuf[:])
			if err != nil {
				return nil, err
			}

			muxServerCloseSession(w, f.SessionID, s)
		}
		return f, nil
	case SessionStatusEnd:
		log.Debugln("server worker %p handling SessionStatusEnd", w)
		s, found := muxServerGetSession(w, f.SessionID)
		if found {
			muxServerCloseSession(w, f.SessionID, s)
		}

		if (f.Option & OptionData) != 0 {
			err = muxUtilDiscardData(conn)
			if err != nil {
				log.Errorln("muxServerHandleFrame: error when discarding data: %v", err)
				return nil, err
			}
		}
		return f, nil
	case SessionStatusNew:
		log.Debugln("server worker %p handling SessionStatusNew", w)
		if f.NetType != byte(0x01) && f.TargetDomain != "reverse.internal.v2fly.org" && f.TargetDomain != "reverse.internal.example.com" && f.TargetDomain != "reverse.internal.v2ray.com" {
			// Non-TCP
			// Drop silently
			log.Warnln("server worker %p got a non-tcp connection (%d), sessionID=%d, targetDomain=%s, dropping it", w, f.NetType, f.SessionID, f.TargetDomain)
			if (f.Option & OptionData) != 0 {
				err = muxUtilDiscardData(conn)
				if err != nil {
					log.Errorln("muxServerHandleFrame: error when discarding data: %v", err)
					return nil, err
				}
			}
			return f, nil
		}
		sessionConn1, sessionConn2 := net.Pipe()
		sessionConnMeta := &C.Metadata{}
		sessionConnMeta.NetWork = C.TCP
		sessionConnMeta.Type = C.TUNNEL
		sessionConnMeta.DNSMode = C.DNSNormal
		sessionConnMeta.SpecialRules = w.PayloadConnSubRule
		sessionConnMeta.DstPort = f.TargetPort
		sessionConnMeta.DstIP = f.TargetIP
		sessionConnMeta.Host = f.TargetDomain
		sessionConnMeta.InName = "BridgeWithRule:" + w.fromBridgeWithRule

		go func() {
			log.Debugln("reverse: new reverse connection: serverWorker=%p, sessionID=%d, dest= %s / %s : %d", w, f.SessionID, f.TargetDomain, f.TargetIP.String(), f.TargetPort)
			if f.TargetDomain == "reverse.internal.v2fly.org" || f.TargetDomain == "reverse.internal.example.com" || f.TargetDomain == "reverse.internal.v2ray.com" {
				log.Debugln("reverse: the reverse conn is control connection, piping it to black hole: serverWorker=%p, sessionID=%d, dest= %s / %s : %d", w, f.SessionID, f.TargetDomain, f.TargetIP.String(), f.TargetPort)
				io.Copy(io.Discard, sessionConn2)
			} else {
				Tunnel.HandleTCPConn(sessionConn2, sessionConnMeta)
			}
			log.Debugln("reverse: end reverse connection: serverWorker=%p, sessionID=%d, dest= %s / %s : %d", w, f.SessionID, f.TargetDomain, f.TargetIP.String(), f.TargetPort)
		}()

		s := &MuxSession{
			downstreamWriter: sessionConn1,
		}

		muxServerAddSession(w, f.SessionID, s)
		thisSessionID := f.SessionID
		go func() {
			rbuf := [32 * 1024]byte{}
			wbuf := &bytes.Buffer{}
			var err error
			// From io.Copy().
			for {
				nr, er := sessionConn1.Read(rbuf[:])
				if nr > 0 {
					// outF := FrameMetadata{
					// 	SessionID: thisSessionID,
					// 	SessionStatus: SessionStatusKeep,
					// 	Option: OptionData,
					// }

					wbuf.Reset()
					binary.Write(wbuf, binary.BigEndian, uint16(4))
					binary.Write(wbuf, binary.BigEndian, thisSessionID)
					wbuf.WriteByte(SessionStatusKeep)
					wbuf.WriteByte(OptionData)
					binary.Write(wbuf, binary.BigEndian, uint16(nr))
					wbuf.Write(rbuf[:nr])

					muxToWrite := wbuf.Bytes()

					nw, ew := conn.Write(muxToWrite)
					if nw < 0 || len(muxToWrite) < nw {
						nw = 0
						if ew == nil {
							ew = errors.New("invalid write result")
						}
					}
					if ew != nil {
						err = ew
						break
					}
					if len(muxToWrite) != nw {
						err = io.ErrShortWrite
						break
					}
				}
				if er != nil {
					if er != io.EOF {
						err = er
					}
					break
				}
			}
			if err != nil {
				log.Warnln("reverse: the serverWorker=%p, sessionID=%d sessionConn -> muxConn copy coroutine stopped because of error: %v", w, thisSessionID, err)
			} else {
				log.Debugln("reverse: the serverWorker=%p, sessionID=%d sessionConn -> muxConn copy coroutine stopped without error", w, thisSessionID)
			}

			// Notify remote peer to close this session.
			responseBuf := [6]byte{}
			binary.BigEndian.PutUint16(responseBuf[0:2], uint16(4))
			binary.BigEndian.PutUint16(responseBuf[2:4], f.SessionID)
			responseBuf[4] = SessionStatusEnd
			responseBuf[5] = byte(0x00) // Option
			// net.Pipe() has internal lock
			_, err = conn.Write(responseBuf[:])
			if err != nil {
				log.Warnln("reverse: serverWorker=%p, sessionID=%d sessionConn -> muxConn copy coroutine tried to notify remote peer to close session, err encountered: %v", w, thisSessionID, err)
			}

			sessionConn1.Close()
			muxServerCloseSession(w, thisSessionID, s)
		}()

		if (f.Option & OptionData) != 0 {
			dataLenRaw := [2]byte{}
			_, err := io.ReadFull(conn, dataLenRaw[:])
			if err != nil {
				log.Errorln("muxServerHandleFrame: serverWorker=%p, sessionID=%d reading frame data len: %v", w, f.SessionID, err)
				return nil, err
			}
			dataLen := int(binary.BigEndian.Uint16(dataLenRaw[:]))
			data := make([]byte, dataLen)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				log.Errorln("muxServerHandleFrame: serverWorker=%p, sessionID=%d reading frame data body: %v", w, f.SessionID, err)
				return nil, err
			}
			_, err = s.downstreamWriter.Write(data)
			if err != nil {
				log.Errorln("muxServerHandleFrame: serverWorker=%p, sessionID=%d writing frame data body to downstream: %v", w, f.SessionID, err)

				// Notify remote peer to close this session.
				responseBuf := [6]byte{}
				binary.BigEndian.PutUint16(responseBuf[0:2], uint16(4))
				binary.BigEndian.PutUint16(responseBuf[2:4], f.SessionID)
				responseBuf[4] = SessionStatusEnd
				responseBuf[5] = byte(0x00) // Option
				// net.Pipe() has internal lock
				_, err := conn.Write(responseBuf[:])
				if err != nil {
					muxServerCloseSession(w, f.SessionID, s)
					return nil, err
				}

				muxServerCloseSession(w, f.SessionID, s)
			}
		}

		return f, nil
	default:
		return nil, fmt.Errorf("muxServerHandleFrame: unknown SessionStatus: %d", f.SessionStatus)
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
		case byte(0x00): // net.AddressFamilyIPv4
			if len(b) < (8 + net.IPv4len) {
				return nil, fmt.Errorf("insufficient buffer for ipv4: %d", len(b))
			}
			f.TargetIP, _ = netip.AddrFromSlice(b[8 : 8+net.IPv4len])
		case byte(0x01): // net.AddressFamilyIPv6
			if len(b) < (8 + net.IPv6len) {
				return nil, fmt.Errorf("insufficient buffer for ipv6: %d", len(b))
			}
			f.TargetIP, _ = netip.AddrFromSlice(b[8 : 8+net.IPv6len])
		case byte(0x02): // net.AddressFamilyDomain
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
