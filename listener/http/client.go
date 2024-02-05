package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

func newClient(srcConn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// from http.DefaultTransport
			MaxIdleConns:          100,
			IdleConnTimeout:       0,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 0,
			ExpectContinueTimeout: 0,
			DialContext: func(context context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" && network != "tcp6" {
					return nil, errors.New("unsupported network " + network)
				}

				dstAddr := socks5.ParseAddr(address)
				if dstAddr == nil {
					return nil, socks5.ErrAddressNotSupported
				}

				left, right := N.Pipe()

				go tunnel.HandleTCPConn(inbound.NewHTTP(dstAddr, srcConn, right, additions...))

				return left, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
