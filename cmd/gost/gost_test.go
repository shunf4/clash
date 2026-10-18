package gost

import (
	"strings"
	"testing"
)

// TestBuildSSOverSocks checks the configuration assembled for the documented
// one-liner, without starting anything.
func TestBuildSSOverSocks(t *testing.T) {
	entry, err := BuildEntry("socks5h://127.0.0.1:1080", "ss://aes-128-gcm:pw@1.2.3.4:8388")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Name != "inbound" {
		t.Fatalf("listener name = %q", entry.Name)
	}
	if entry.Type != "socks" {
		t.Fatalf("listener type = %q", entry.Type)
	}
	if entry.OutboundType != "ss" {
		t.Fatalf("outbound type = %q", entry.OutboundType)
	}
	raw, err := entry.Render()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"mode: global",
		"log-level: info",
		"find-process-mode: off",
		"store-selected: false",
		"enable: false", // dns
		"proxy: gost-ss-1.2.3.4",
		"udp: true",
		"cipher: aes-128-gcm",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("rendered config misses %q:\n%s", want, raw)
		}
	}
	if strings.Contains(raw, "pw") {
		t.Fatalf("password leaked in --dry-run output:\n%s", raw)
	}
}

// TestBuildDirect checks that omitting -F switches to direct mode.
func TestBuildDirect(t *testing.T) {
	entry, err := BuildEntry("mixed://127.0.0.1:7890", "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := entry.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "mode: direct") || !strings.Contains(raw, "proxy: DIRECT") {
		t.Fatalf("direct mode missing:\n%s", raw)
	}
}

// TestBuildYAMLFragment checks the YAML form of both arguments.
func TestBuildYAMLFragment(t *testing.T) {
	inbound := "type: socks\nlisten: 127.0.0.1\nport: 1080\nudp: false\n"
	outbound := "type: socks5\nserver: 10.0.0.1\nport: 1080\nusername: u\npassword: p\n"
	entry, err := BuildEntry(inbound, outbound)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := entry.Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "gost-socks5-10.0.0.1") {
		t.Fatalf("generated outbound name missing:\n%s", raw)
	}
	if strings.Contains(raw, "password: p") {
		t.Fatalf("password leaked:\n%s", raw)
	}
}

// TestBuildInvalid checks error reporting for malformed input.
func TestBuildInvalid(t *testing.T) {
	if _, err := BuildEntry("socks5h://", ""); err == nil {
		t.Fatalf("missing address should fail")
	}
	if _, err := BuildEntry("type: socks\nlisten: 127.0.0.1\nport: 1080\n", "ss://broken"); err == nil {
		t.Fatalf("invalid ss link should fail")
	}
}

// TestValidate checks that the generated configuration passes the core parser.
func TestValidate(t *testing.T) {
	// The disk guard is not installed in tests, so parsing is allowed to touch
	// the cache; configuration.Parse does not start listeners.
	entry, err := BuildEntry("socks5h://127.0.0.1:1080", "socks5h://10.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if err := entry.Validate(); err != nil {
		t.Fatalf("generated configuration is invalid: %v", err)
	}
}
