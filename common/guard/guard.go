// Package guard provides a process-wide policy switch that lets the mihomo
// core run without touching the disk or the network on its own behalf.
//
// Usage: a command line frontend (for example `mhm gost`) calls DisableDisk
// and/or DisableNet before the core configuration is loaded. Every place in
// the core that would write to the disk or fetch something from the internet
// on behalf of mihomo itself (config/cache/geodata/subscription fetching, UI
// download, core update, ...) asks this package first and, when the policy is
// deny, logs a clear error and panics instead of silently doing nothing.
//
// The policy is intentionally a global, sticky switch rather than a context
// value: mihomo starts background goroutines (updaters, health checks,
// providers, ...) that would otherwise escape a per-call policy, so the whole
// process must share one answer.
//
// When adding a new place that may write to the disk or reach the network in
// the future, guard it with the same short pattern:
//
//	// mod: xx
//	if !guard.DiskAllowed() {
//	    guard.Refuse("disk", "writing foo")
//	}
//
// or, for network access:
//
//	// mod: xx
//	if !guard.NetAllowed() {
//	    guard.Refuse("net", "fetching foo")
//	}
package guard

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/log"
)

// ErrDisabled is returned (or wrapped) by guarded functions when the caller
// asked for the operation to be blocked by the current policy.
var ErrDisabled = errors.New("operation blocked: this process was started with disk/network access disabled")

var (
	diskAllowed = atomic.NewBool(true)
	netAllowed  = atomic.NewBool(true)
)

// DiskAllowed reports whether mihomo is allowed to write to the disk.
func DiskAllowed() bool {
	return diskAllowed.Load()
}

// NetAllowed reports whether mihomo is allowed to reach the network on its own
// behalf. This does not affect proxying user traffic; it only covers mihomo
// initiated requests such as geo data, subscription and UI downloads.
func NetAllowed() bool {
	return netAllowed.Load()
}

// DisableDisk forbids all disk writes made by mihomo. It is sticky for the
// lifetime of the process.
func DisableDisk() {
	diskAllowed.Store(false)
}

// DisableNet forbids all mihomo initiated network requests. It is sticky for
// the lifetime of the process.
func DisableNet() {
	netAllowed.Store(false)
}

// AllowDisk re-enables disk writes (mainly useful for tests).
func AllowDisk() {
	diskAllowed.Store(true)
}

// AllowNet re-enables mihomo initiated network requests (mainly useful for
// tests).
func AllowNet() {
	netAllowed.Store(true)
}

// Refuse reports a blocked operation loudly and terminates the process.
//
// Silently skipping a write or a download would make the process look
// successful while the user's expectation (the file was created, the data was
// refreshed, ...) is not met, so failing hard is the conservative choice.
func Refuse(kind, action string) {
	msg := fmt.Sprintf("mihomo is not allowed to use the %s (%s), %s", kind, action, ErrDisabled.Error())
	log.Errorln("%s", msg)
	panic(msg)
}
