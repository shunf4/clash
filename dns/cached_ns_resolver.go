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
	cache          *cache.LruCache
	lastNameserver string
	mu             sync.Mutex
	clientName     string
	cacheTimeout   time.Duration
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
	ipRaw, _ = cnc.cache.Get(cnc.clientName)
	if ipRaw == nil {
		var ipStr string
		isNew := false

		nameservers, err := cnc.getNameservers()
		if err != nil {
			return nil, err
		}
		if len(nameservers) == 0 {
			if cnc.lastNameserver == "" {
				err := fmt.Errorf("%s: No nameserver was fetched, storing <IPv4zero> into cache", cnc.clientName)
				log.Warnln(err.Error())
				cnc.cache.SetWithExpire(cnc.clientName, net.IPv4zero, time.Now().Add(cnc.cacheTimeout))
				cnc.mu.Unlock()
				return nil, err
			} else {
				err := fmt.Errorf("%s: No nameserver was fetched, storing <IPv4zero> into cache. Using lastNameserver %s", cnc.clientName, cnc.lastNameserver)
				log.Warnln(err.Error())
				cnc.cache.SetWithExpire(cnc.clientName, net.IPv4zero, time.Now().Add(cnc.cacheTimeout))
				ipStr = cnc.lastNameserver
			}
		} else {
			ipStr = nameservers[0]
			if ipStr == "" {
				if cnc.lastNameserver == "" {
					err := fmt.Errorf("%s: IP string is empty, storing <IPv4zero> into cache", cnc.clientName)
					log.Warnln(err.Error())
					cnc.cache.SetWithExpire(cnc.clientName, net.IPv4zero, time.Now().Add(cnc.cacheTimeout))
					cnc.mu.Unlock()
					return nil, err
				} else {
					err := fmt.Errorf("%s: IP string is empty, storing <IPv4zero> into cache. Using lastNameserver %s", cnc.clientName, cnc.lastNameserver)
					log.Warnln(err.Error())
					ipStr = cnc.lastNameserver
					cnc.cache.SetWithExpire(cnc.clientName, net.IPv4zero, time.Now().Add(cnc.cacheTimeout))
				}
			} else {
				isNew = true
			}
		}

		ip = net.ParseIP(ipStr)
		if ip == nil {
			cnc.cache.SetWithExpire(cnc.clientName, net.IPv4zero, time.Now().Add(cnc.cacheTimeout))
			cnc.mu.Unlock()
			return nil, fmt.Errorf("%s: parse IP string (%v) error, storing <IPv4zero> into cache", cnc.clientName, ipStr)
		}

		cnc.lastNameserver = ipStr

		if isNew {
			log.Infoln("%s: got nameserver IP %s and store it into cache", cnc.clientName, ipStr)
			cnc.cache.SetWithExpire(cnc.clientName, ip, time.Now().Add(cnc.cacheTimeout))
		}
	} else {
		ip = ipRaw.(net.IP)
		if ip.Equal(net.IPv4zero) {
			cnc.mu.Unlock()
			err := fmt.Errorf("got cached IP <IPv4zero>, not resolving (until next update)")
			log.Warnln(err.Error())
			return nil, err
		}
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
