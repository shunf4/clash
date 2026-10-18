package nat

import (
	"net"

	"github.com/metacubex/mihomo/common/atomic"
	C "github.com/metacubex/mihomo/constant"
)

type writeBackProxy struct {
	wb atomic.TypedValue[C.WriteBack]
	// mod: remote UDP resolution. Before the first outbound packet updates the
	// write-back target (see packetSender.Process) the tunnel still needs to
	// deliver replies, so keep the default target created with the NAT session.
	defaultWB C.WriteBack
}

func (w *writeBackProxy) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	if wb := w.wb.Load(); wb != nil {
		return wb.WriteBack(b, addr)
	}
	return w.defaultWB.WriteBack(b, addr)
}

func (w *writeBackProxy) UpdateWriteBack(wb C.WriteBack) {
	w.wb.Store(wb)
}

func NewWriteBackProxy(wb C.WriteBack) C.WriteBackProxy {
	return newWriteBackProxy(wb, wb)
}

// NewWriteBackProxyDefault creates a proxy that uses defaultWB until the first
// packet updates the write-back target.
//
// mod: remote UDP resolution: see writeBackProxy.defaultWB.
func NewWriteBackProxyDefault(withDefault C.WriteBack, defaultWB C.WriteBack) C.WriteBackProxy {
	return newWriteBackProxy(withDefault, defaultWB)
}

func newWriteBackProxy(wb C.WriteBack, defaultWB C.WriteBack) C.WriteBackProxy {
	w := &writeBackProxy{defaultWB: defaultWB}
	w.UpdateWriteBack(wb)
	return w
}
