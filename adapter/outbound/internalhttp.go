package outbound

import (
	"context"
	"fmt"
	"net"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

type InternalHTTP struct {
	*Base
}

// DialContext implements C.ProxyAdapter
func (ih *InternalHTTP) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	return ih.DialContextWithDialer(ctx, nil, metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (ih *InternalHTTP) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	target := metadata.Host
	var conn net.Conn
	if target == "CLASHRAY-HTTP-REDIRECT" {
		conn = tunnel.BgHandleInternalHTTPClashrayHTTPRedirect()
	} else if target == "CLASHRAY-TEST" {
		conn = tunnel.BgHandleInternalHTTPClashrayTest(metadata)
	} else if target == "CLASHRAY-SEND" {
		conn = tunnel.BgHandleInternalHTTPClashraySend()
	} else {
		return nil, fmt.Errorf("internalHTTP outbound: invalid target(metadata.Host): %s", target)
	}

	return NewConn(conn, ih), nil
}

// SupportWithDialer implements C.ProxyAdapter
func (ih *InternalHTTP) SupportWithDialer() C.NetWork {
	return C.TCP
}

type InternalHTTPOption struct {
	Name string `proxy:"name"`
}

func NewInternalHTTP(option InternalHTTPOption) *InternalHTTP {
	return &InternalHTTP{
		Base: &Base{
			name:   option.Name,
			tp:     C.InternalHTTP,
			udp:    false,
			prefer: C.DualStack,
		},
	}
}
