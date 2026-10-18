package cli

import (
	"strings"
	"testing"

	M "github.com/metacubex/mihomo/common/yaml"
)

func TestLooksLikeURL(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"socks5h://127.0.0.1:1080", true},
		{"vmess://eyJhZGQiOiIxLjIuMy40In0=", true},
		{"type: socks\nport: 1080", false},
		{"socks5h://127.0.0.1:1080\nudp: true", false},
		{"not a url", false},
	}
	for _, c := range cases {
		if got := LooksLikeURL(c.in); got != c.want {
			t.Errorf("LooksLikeURL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestInboundURLDefaults(t *testing.T) {
	in, err := ParseInbound("socks5h://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if in.Type != "socks" {
		t.Fatalf("type = %q, want socks", in.Type)
	}
	if in.Fields["udp"] != true {
		t.Fatalf("udp should default to true")
	}
	users, ok := in.Fields["users"].([]Map)
	if !ok || len(users) != 1 || users[0]["username"] != "user" || users[0]["password"] != "pass" {
		t.Fatalf("users = %#v", in.Fields["users"])
	}
	if _, err := ParseInbound("mixed://127.0.0.1:7890"); err != nil {
		t.Fatalf("mixed inbound: %v", err)
	}
	// A missing host means "all interfaces", the port is still required.
	in, err = ParseInbound("socks5h://:1080")
	if err != nil {
		t.Fatalf("host-less inbound: %v", err)
	}
	if in.Fields["listen"] != "0.0.0.0" {
		t.Fatalf("listen = %#v", in.Fields["listen"])
	}
	if _, err := ParseInbound("socks5h://"); err == nil {
		t.Fatalf("missing port should fail")
	}
}

func TestInboundYAML(t *testing.T) {
	in, err := ParseInbound("type: socks\nlisten: 127.0.0.1\nport: 1080\nusers:\n  - username: a\n    password: b\n")
	if err != nil {
		t.Fatal(err)
	}
	if in.Fields["udp"] != true {
		t.Fatalf("udp should default to true for socks")
	}
	if in.Fields["listen"] != "127.0.0.1" {
		t.Fatalf("listen = %#v", in.Fields["listen"])
	}
}

func TestOutboundSS(t *testing.T) {
	out, err := ParseOutbound("ss://aes-128-gcm:secret@1.2.3.4:8388")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "ss" || out.Fields["cipher"] != "aes-128-gcm" || out.Fields["password"] != "secret" {
		t.Fatalf("fields = %#v", out.Fields)
	}
	if out.Fields["udp"] != true {
		t.Fatalf("udp should default to true")
	}
	out, err = ParseOutbound("ss://aes-128-gcm:secret@1.2.3.4:8388?plugin=obfs-local;obfs=http;obfs-host=bing.com")
	if err != nil {
		t.Fatal(err)
	}
	if out.Fields["plugin"] != "obfs" {
		t.Fatalf("plugin = %#v", out.Fields["plugin"])
	}
}

func TestOutboundNestedQuery(t *testing.T) {
	out, err := ParseOutbound("trojan://pw@host:443?sni=x&network=ws&ws-opts.path=/p&ws-opts.headers.Host=h.com")
	if err != nil {
		t.Fatal(err)
	}
	wsOpts, ok := out.Fields["ws-opts"].(Map)
	if !ok {
		t.Fatalf("ws-opts = %#v", out.Fields["ws-opts"])
	}
	if wsOpts["path"] != "/p" {
		t.Fatalf("path = %#v", wsOpts["path"])
	}
	headers, ok := wsOpts["headers"].(Map)
	if !ok || headers["Host"] != "h.com" {
		t.Fatalf("headers = %#v", wsOpts["headers"])
	}
	if out.Fields["password"] != "pw" {
		t.Fatalf("password = %#v", out.Fields["password"])
	}
}

func TestOutboundShareLinkAliases(t *testing.T) {
	// Share link parameter names are translated to configuration names, while
	// configuration names keep working as-is.
	out, err := ParseOutbound("vless://uuid@host:443?security=reality&sni=x&fp=chrome&pbk=pk&sid=ab&type=grpc&serviceName=svc&allowInsecure=1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Fields["tls"] != true {
		t.Fatalf("security=reality should enable tls: %#v", out.Fields)
	}
	if out.Fields["network"] != "grpc" {
		t.Fatalf("network = %#v", out.Fields["network"])
	}
	if out.Fields["client-fingerprint"] != "chrome" {
		t.Fatalf("client-fingerprint = %#v", out.Fields["client-fingerprint"])
	}
	if out.Fields["skip-cert-verify"] != true {
		t.Fatalf("skip-cert-verify = %#v", out.Fields["skip-cert-verify"])
	}
	realityOpts, ok := out.Fields["reality-opts"].(Map)
	if !ok || realityOpts["public-key"] != "pk" || realityOpts["short-id"] != "ab" {
		t.Fatalf("reality-opts = %#v", out.Fields["reality-opts"])
	}
	grpcOpts, ok := out.Fields["grpc-opts"].(Map)
	if !ok || grpcOpts["grpc-service-name"] != "svc" {
		t.Fatalf("grpc-opts = %#v", out.Fields["grpc-opts"])
	}
}

// TestOutboundConfigurationNamesWin checks that a configuration name is not
// overwritten by the share link alias of the same field.
func TestOutboundConfigurationNamesWin(t *testing.T) {
	out, err := ParseOutbound("trojan://pw@host:443?sni=x&allowInsecure=1&skip-cert-verify=false")
	if err != nil {
		t.Fatal(err)
	}
	if out.Fields["sni"] != "x" {
		t.Fatalf("sni = %#v", out.Fields["sni"])
	}
	if out.Fields["skip-cert-verify"] != false {
		t.Fatalf("skip-cert-verify = %#v", out.Fields["skip-cert-verify"])
	}
}

func TestOutboundYAMLUnknownKeys(t *testing.T) {
	out, err := ParseOutbound("type: socks5\nserver: 1.2.3.4\nport: 1080\nnot-a-field: 1\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, exist := out.Fields["not-a-field"]; exist {
		t.Fatalf("unknown field should be dropped")
	}
}

func TestMaskSecrets(t *testing.T) {
	out, err := ParseOutbound("ss://aes-128-gcm:secret@1.2.3.4:8388")
	if err != nil {
		t.Fatal(err)
	}
	masked := MaskMap("", out.Fields)
	if masked["password"] != MaskedValue {
		t.Fatalf("password not masked: %#v", masked["password"])
	}
	if masked["cipher"] != "aes-128-gcm" {
		t.Fatalf("cipher should not be masked")
	}
}

func TestCoerce(t *testing.T) {
	if v := Coerce("true"); v != true {
		t.Fatalf("%#v", v)
	}
	if v := Coerce("443"); v != int64(443) {
		t.Fatalf("%#v", v)
	}
	if v, ok := Coerce("h2,h3").([]string); !ok || len(v) != 2 {
		t.Fatalf("%#v", v)
	}
	if v := Coerce("/ws"); v != "/ws" {
		t.Fatalf("%#v", v)
	}
}

func TestVmessShareLink(t *testing.T) {
	// V2RayN JSON share link, base64 of {"add":"1.2.3.4","port":"443","id":"uuid","net":"ws","path":"/p","host":"h","tls":"tls","ps":"name"}
	link := "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoidXVpZCIsIm5ldCI6IndzIiwicGF0aCI6Ii9wIiwiaG9zdCI6ImgiLCJ0bHMiOiJ0bHMiLCJwcyI6Im5hbWUifQ=="
	out, err := ParseOutbound(link)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "vmess" || out.Fields["server"] != "1.2.3.4" || out.Fields["uuid"] != "uuid" {
		t.Fatalf("fields = %#v", out.Fields)
	}
	if out.Fields["network"] != "ws" || out.Fields["tls"] != true {
		t.Fatalf("transport fields = %#v", out.Fields)
	}
	if out.Name != "name" {
		t.Fatalf("name = %q", out.Name)
	}
}

func TestDocumentMaskedYAML(t *testing.T) {
	doc := NewDocument()
	doc.SetMap("mode", "global")
	doc.Append("proxies", Map{"name": "p", "password": "secret", "nested": Map{"token": "t"}})
	out, err := doc.MaskedYAML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "secret") || strings.Contains(out, ": t") {
		t.Fatalf("secrets leaked:\n%s", out)
	}
	if !strings.Contains(out, "mode: global") {
		t.Fatalf("mode missing:\n%s", out)
	}
	// The output must be a valid YAML document with the expected nesting.
	raw, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := M.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("generated YAML is invalid: %v\n%s", err, raw)
	}
	proxies, ok := parsed["proxies"].([]any)
	if !ok || len(proxies) != 1 {
		t.Fatalf("proxies = %#v\n%s", parsed["proxies"], raw)
	}
	proxy, ok := proxies[0].(map[string]any)
	if !ok || proxy["password"] != "secret" || proxy["name"] != "p" {
		t.Fatalf("proxy = %#v\n%s", proxies[0], raw)
	}
	if !strings.Contains(raw, "proxies:\n  - ") {
		t.Fatalf("proxies list not indented as YAML:\n%s", raw)
	}
}
