package cli

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/log"
)

// socksLikeInbound are the inbound types that understand SOCKS style targets.
var socksLikeInbound = map[string]bool{
	"socks": true,
	"mixed": true,
	"http":  true,
}

// IsSocksLikeInbound reports whether a listener type understands SOCKS style
// targets, which means it relays UDP as well.
func IsSocksLikeInbound(typ string) bool {
	return socksLikeInbound[typ]
}

// inboundByType maps listener types to the concrete option type used by the
// regular listener decoder. The parser in the listener package is not
// importable here (it would create an import cycle through the adapter
// package), so the option types are referenced directly; the structure decoder
// only reads their field tags, which are identical.
func inboundByType(typ string) any {
	switch typ {
	case "socks":
		return &inbound.SocksOption{UDP: true}
	case "http":
		return &inbound.HTTPOption{}
	case "mixed":
		return &inbound.MixedOption{UDP: true}
	case "shadowsocks":
		return &inbound.ShadowSocksOption{UDP: true}
	case "snell":
		return &inbound.SnellOption{UDP: true}
	case "vmess":
		return &inbound.VmessOption{}
	case "vless":
		return &inbound.VlessOption{}
	case "trojan":
		return &inbound.TrojanOption{}
	case "anytls":
		return &inbound.AnyTLSOption{}
	case "hysteria2":
		return &inbound.Hysteria2Option{}
	case "tuic":
		return &inbound.TuicOption{MaxIdleTime: 15000, AuthenticationTimeout: 1000, ALPN: []string{"h3"}, MaxUdpRelayPacketSize: 1500, CongestionController: "bbr"}
	case "shadowquic":
		return &inbound.ShadowQuicOption{MaxIdleTime: 30000, ALPN: []string{"h3"}, MaxDatagramFrameSize: 1400, CongestionController: "bbr", ZeroRTT: true}
	case "mieru":
		return &inbound.MieruOption{}
	case "sudoku":
		return &inbound.SudokuOption{}
	case "trusttunnel":
		return &inbound.TrustTunnelOption{}
	case "tunnel":
		return &inbound.TunnelOption{}
	case "tun":
		return &inbound.TunOption{Stack: "mips", DNSHijack: []string{"0.0.0.0:53"}}
	case "tproxy":
		return &inbound.TProxyOption{UDP: true}
	case "redir":
		return &inbound.RedirOption{}
	default:
		return nil
	}
}

// inboundDefaults holds the defaults applied to a YAML inbound fragment of the
// given type before it is validated. UDP is on by default for every type that
// relays it, matching the "just works" goal; a user fragment can turn it off.
var inboundDefaults = map[string]Map{
	"socks":       {"udp": true},
	"mixed":       {"udp": true},
	"http":        {},
	"shadowsocks": {"udp": true},
	"snell":       {"udp": true},
	"vmess":       {},
	"vless":       {},
	"trojan":      {},
	"anytls":      {},
	"hysteria2":   {},
	"tuic":        {"max-idle-time": 15000, "authentication-timeout": 1000},
	"shadowquic":  {"udp": true},
	"mieru":       {},
	"sudoku":      {},
	"trusttunnel": {},
	"tunnel":      {"network": []string{"tcp"}},
	"tun":         {},
}

// InboundFieldNames returns the configuration keys an inbound of the given
// type accepts, derived from the option struct tags.
func InboundFieldNames(typ string) map[string]bool {
	if option := inboundByType(typ); option != nil {
		return structKeys(option, "inbound")
	}
	// Unknown types are passed through untouched; the core reports them.
	return nil
}

// validateInbound decodes the fragment with the same decoder as the regular
// listener parser. The returned error already lists every invalid field, and
// validation repeats the load time decoder exactly.
func validateInbound(fields Map) error {
	typ, _ := fields["type"].(string)
	option := inboundByType(typ)
	if option == nil {
		return fmt.Errorf("unsupported inbound type: %s", typ)
	}
	// Fill the defaults of the type, so required fields validated here match
	// what the core would decode from the generated configuration.
	if defaults, ok := inboundDefaults[typ]; ok {
		fields = MergeDefaults(defaults, fields)
	}
	return decoder().Decode(fields, option)
}

// outboundByType maps outbound types to the concrete option types used by the
// regular proxy parser.
func outboundByType(typ string) any {
	switch typ {
	case "ss":
		return &outbound.ShadowSocksOption{}
	case "ssr":
		return &outbound.ShadowSocksROption{}
	case "socks5":
		return &outbound.Socks5Option{}
	case "http":
		return &outbound.HttpOption{}
	case "vmess":
		return &outbound.VmessOption{}
	case "vless":
		return &outbound.VlessOption{}
	case "snell":
		return &outbound.SnellOption{}
	case "trojan":
		return &outbound.TrojanOption{}
	case "hysteria":
		return &outbound.HysteriaOption{}
	case "hysteria2":
		return &outbound.Hysteria2Option{}
	case "wireguard":
		return &outbound.WireGuardOption{}
	case "tuic":
		return &outbound.TuicOption{}
	case "shadowquic":
		return &outbound.ShadowQuicOption{}
	case "gost-relay":
		return &outbound.GostRelayOption{}
	case "direct":
		return &outbound.DirectOption{}
	case "dns":
		return &outbound.DnsOption{}
	case "reject":
		return &outbound.RejectOption{}
	case "rematch":
		return &outbound.RematchOption{}
	case "ssh":
		return &outbound.SshOption{}
	case "mieru":
		return &outbound.MieruOption{}
	case "anytls":
		return &outbound.AnyTLSOption{}
	case "sudoku":
		return &outbound.SudokuOption{}
	case "masque":
		return &outbound.MasqueOption{}
	case "trusttunnel":
		return &outbound.TrustTunnelOption{}
	case "openvpn":
		return &outbound.OpenVPNOption{}
	case "tailscale":
		return &outbound.TailscaleOption{}
	case "zerotier":
		return &outbound.ZeroTierOption{}
	case "easytier":
		return &outbound.EasyTierOption{}
	default:
		return nil
	}
}

// outboundUDPDefault reports whether UDP is enabled by default for the type.
func outboundUDPDefault(typ string) bool {
	switch typ {
	case "ss", "ssr", "socks5", "trojan", "vmess", "vless", "snell", "hysteria2",
		"tuic", "anytls", "shadowquic", "mieru", "wireguard", "masque", "openvpn",
		"trusttunnel", "sudoku", "tailscale", "zerotier", "easytier":
		return true
	}
	return false
}

// OutboundFieldNames returns the configuration keys an outbound of the given
// type accepts, derived from the option struct tags.
func OutboundFieldNames(typ string) map[string]bool {
	if option := outboundByType(typ); option != nil {
		return structKeys(option, "proxy")
	}
	return nil
}

// validateProxy decodes the fragment with the regular proxy decoder, which
// enforces required fields and type conversions exactly as a configuration file
// would. The full adapter is not built here: some constructors start background
// work (easy tier, tailscale, ...) that must only run once, when the generated
// configuration is loaded.
func validateProxy(fields Map) error {
	typ, _ := fields["type"].(string)
	option := outboundByType(typ)
	if option == nil {
		return fmt.Errorf("unsupported outbound type: %s", typ)
	}
	return proxyDecoder().Decode(fields, option)
}

// structKeys collects the configuration keys of a struct, following the tag of
// the decoder. Embedded structs are included.
func structKeys(option any, tag string) map[string]bool {
	keys := map[string]bool{}
	collectStructKeys(reflect.TypeOf(option), tag, keys)
	return keys
}

func collectStructKeys(t reflect.Type, tag string, keys map[string]bool) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" { // unexported
			continue
		}
		if field.Anonymous {
			// BasicOption and similar embedded structs are decoded in place, so
			// their keys are accepted at the same level.
			if elem := field.Type; elem.Kind() == reflect.Struct || (elem.Kind() == reflect.Pointer && elem.Elem().Kind() == reflect.Struct) {
				collectStructKeys(elem, tag, keys)
				continue
			}
		}
		parts := strings.Split(field.Tag.Get(tag), ",")
		name := parts[0]
		if name == "" {
			name = field.Name
		}
		if name == "-" {
			continue
		}
		// Nested structs are filled from sub maps; only the parent key is a
		// top level key.
		keys[strings.ToLower(name)] = true
	}
}

// FilterKeys drops keys that the configuration decoder of the given type does
// not accept, reporting them. A nil key set (unknown type) keeps everything.
func FilterKeys(fields Map, accepted map[string]bool, kind, typ string) Map {
	if accepted == nil {
		return fields
	}
	removed := make([]string, 0)
	for key := range fields {
		if accepted[strings.ToLower(key)] {
			continue
		}
		removed = append(removed, key)
		delete(fields, key)
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		log.Warnln("mhm gost: %s (%s): ignoring unknown option(s): %s", kind, typ, strings.Join(removed, ", "))
	}
	return fields
}
