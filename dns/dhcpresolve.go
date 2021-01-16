package dns

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/log"
	D "github.com/miekg/dns"
)

type dhcpNameserversClient struct {
	*D.Client
	cache *cache.Cache
}

func (dnc *dhcpNameserversClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return dnc.ExchangeContext(context.Background(), m)
}

func (dnc *dhcpNameserversClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	var ipRaw interface{}
	var ip net.IP
	// get DHCP nameservers from cache
	ipRaw = dnc.cache.Get("dhcpnameserver")
	if ipRaw == nil {
		nameservers, _, _ := GetCurrDhcpNameservers()
		if len(nameservers) == 0 {
			log.Warnln("dhcpnameservers: No current DHCP DNS server was fetched. There might be an error")
			return nil, errors.New("dhcpnameservers: No current DHCP DNS server was fetched. There might be an error")
		}
		ipStr := nameservers[0]
		if ipStr == "" {
			log.Warnln("dhcpnameservers: IP string is empty")
			return nil, errors.New("dhcpnameservers: IP string is empty")
		}

		ip = net.ParseIP(ipStr)
		if ip == nil {
			return nil, errors.New("dhcpnameservers: parse IP string error")
		}

		log.Infoln("dhcpnameservers: got DHCP DNS IP %s and store it into cache", ipStr)
		dnc.cache.Put("dhcpnameserver", ip, 5 * time.Second)
	} else {
		ip = ipRaw.(net.IP)
	}

	d, err := dialer.Dialer()
	if err != nil {
		return nil, err
	}

	dnc.Client.Dialer = d

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, _, err := dnc.Client.Exchange(m, net.JoinHostPort(ip.String(), "53"))
		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}
