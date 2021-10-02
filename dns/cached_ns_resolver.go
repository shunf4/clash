package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/log"
	D "github.com/miekg/dns"
)

type cachedNameserversClient struct {
	*D.Client
	cache          *cache.Cache
	lastNameserver string
	mu             sync.Mutex
	clientName     string
	getNameservers func() (nameservers []string, err error)
}

func (cnc *cachedNameserversClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return cnc.ExchangeContext(context.Background(), m)
}

// miekg/dns ExchangeContext doesn't respond to context cancel.
// this is a workaround
type dnsClientResult struct {
	msg *D.Msg
	err error
}

func (cnc *cachedNameserversClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	var ipRaw interface{}
	var ip net.IP

	cnc.mu.Lock()

	// get nameservers from cache
	ipRaw = cnc.cache.Get(cnc.clientName)
	if ipRaw == nil {
		var ipStr string
		isNew := false

		nameservers, err := cnc.getNameservers()
		if err != nil {
			return nil, err
		}
		if len(nameservers) == 0 {
			if cnc.lastNameserver == "" {
				err := fmt.Errorf("%s: No nameserver was fetched", cnc.clientName)
				log.Warnln(err.Error())
				cnc.mu.Unlock()
				return nil, err
			} else {
				err := fmt.Errorf("%s: No nameserver was fetched. Using lastNameserver %s", cnc.clientName, cnc.lastNameserver)
				log.Warnln(err.Error())
				ipStr = cnc.lastNameserver
			}
		} else {
			ipStr = nameservers[0]
			if ipStr == "" {
				if cnc.lastNameserver == "" {
					err := fmt.Errorf("%s: IP string is empty", cnc.clientName)
					log.Warnln(err.Error())
					cnc.mu.Unlock()
					return nil, err
				} else {
					err := fmt.Errorf("%s: IP string is empty. Using lastNameserver %s", cnc.clientName, cnc.lastNameserver)
					log.Warnln(err.Error())
					ipStr = cnc.lastNameserver
				}
			} else {
				isNew = true
			}
		}

		ip = net.ParseIP(ipStr)
		if ip == nil {
			cnc.mu.Unlock()
			return nil, fmt.Errorf("%s: parse IP string (%v) error", cnc.clientName, ipStr)
		}

		cnc.lastNameserver = ipStr

		if isNew {
			log.Infoln("%s: got nameserver IP %s and store it into cache", cnc.clientName, ipStr)
			cnc.cache.Put(cnc.clientName, ip, 5*time.Second)
		}
	} else {
		ip = ipRaw.(net.IP)
	}

	cnc.mu.Unlock()

	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(ip.String(), "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ch := make(chan dnsClientResult, 1)
	go func() {
		msg, _, err := cnc.Client.ExchangeWithConn(m, &D.Conn{
			Conn:         conn,
			UDPSize:      cnc.Client.UDPSize,
			TsigSecret:   cnc.Client.TsigSecret,
			TsigProvider: cnc.Client.TsigProvider,
		})
		ch <- dnsClientResult{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}
