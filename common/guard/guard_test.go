package guard

import (
	"testing"
)

// TestPolicy covers the sticky switch semantics and the default (allow) state.
// Refuse panics by design; only the policy predicates are exercised here since a
// panic spawned by a background goroutine would terminate the test binary.
func TestPolicy(t *testing.T) {
	if !DiskAllowed() || !NetAllowed() {
		t.Fatalf("default policy must allow both disk and network")
	}
	DisableDisk()
	if DiskAllowed() {
		t.Fatalf("disk must be denied after DisableDisk")
	}
	DisableNet()
	if NetAllowed() {
		t.Fatalf("network must be denied after DisableNet")
	}
	AllowDisk()
	AllowNet()
	if !DiskAllowed() || !NetAllowed() {
		t.Fatalf("policy must be re-enabled")
	}
}
