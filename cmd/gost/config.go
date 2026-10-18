package gost

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/cmd/gost/cli"
	"github.com/metacubex/mihomo/config"
)

// directProxy is the proxy name used when -F is omitted.
const directProxy = "DIRECT"

// Entry is a fully built, ready to load configuration.
type Entry struct {
	// Name and Type describe the inbound listener, used to verify that the
	// listener is really serving after the core has been loaded.
	Name string
	Type string
	// OutboundType is empty when -F was omitted (direct internet access).
	OutboundType string
	// Raw is the generated configuration document.
	Raw *cli.Document
	// config is the marshalled YAML document fed to hub.Parse.
	config []byte
}

// buildEntry parses the command line values and assembles the configuration.
func buildEntry(opts *options) (*Entry, error) {
	return BuildEntry(opts.inbound, opts.outbound)
}

// BuildEntry parses -L/-F and assembles the configuration.
func BuildEntry(inboundArg, outboundArg string) (*Entry, error) {
	inbound, err := cli.ParseInbound(inboundArg)
	if err != nil {
		return nil, fmt.Errorf("invalid -L: %w", err)
	}
	var outbound *cli.Outbound
	if strings.TrimSpace(outboundArg) != "" {
		outbound, err = cli.ParseOutbound(outboundArg)
		if err != nil {
			return nil, fmt.Errorf("invalid -F: %w", err)
		}
	}
	return assemble(inbound, outbound)
}

// Validate parses the generated configuration through the same parser the core
// uses at load time. It catches mistakes the field level validation can not
// see (listener wiring, mode, ...) without starting anything.
func (e *Entry) Validate() error {
	parsed, err := config.Parse(e.config)
	if err != nil {
		return err
	}
	// Parsed proxies may own background resources; release them to keep the
	// check side effect free.
	for _, proxy := range parsed.Proxies {
		_ = proxy.Close()
	}
	return nil
}

// Render returns the configuration in YAML form with secrets masked.
func (e *Entry) Render() (string, error) {
	return e.Raw.MaskedYAML()
}

// Warnings returns the warnings to print before the listener starts.
func (e *Entry) Warnings() []string {
	warnings := make([]string, 0, 2)
	if cli.IsSocksLikeInbound(e.Type) {
		warnings = append(warnings, "the socks listener does not resolve names itself; whether a "+
			"destination host name is resolved locally or by the server depends on the client (use "+
			"socks5h, for example curl --socks5-hostname, for remote resolution)")
	}
	if e.Raw.InboundUDP() {
		if e.udpDomainCapable() {
			warnings = append(warnings, "UDP relay is enabled; UDP packets are forwarded through the "+
				"outbound and domain destinations are resolved remotely by it")
		} else {
			warnings = append(warnings, fmt.Sprintf("UDP relay is enabled, but the %q outbound can not "+
				"carry a domain name per packet, so UDP destinations are resolved locally (possible DNS leak)", e.OutboundType))
		}
	}
	return warnings
}

// udpDomainCapable reports whether the outbound can carry a domain name to its
// upstream server, so UDP targets are not resolved locally.
//
// Only a few outbound protocols carry the destination address in every packet,
// and only for them the tunnel skips the local lookup (see the remote UDP
// resolution code in adapter/outbound and tunnel/connection.go).
func (e *Entry) udpDomainCapable() bool {
	switch e.OutboundType {
	case "", "direct": // direct access resolves locally, no server to leak the name to
		return true
	case "ss", "ssr", "socks5", "snell":
		return true
	}
	return false
}

// assemble lays out the in-memory configuration. Everything is explicit so the
// behaviour is easy to reason about and inspect with --dry-run.
func assemble(inbound *cli.Inbound, outbound *cli.Outbound) (*Entry, error) {
	doc := cli.NewDocument()

	mode := "direct"
	proxyName := directProxy
	if outbound != nil {
		mode = "global"
		proxyName = outbound.Name
	}

	doc.SetMap("mode", mode)
	doc.SetMap("dns", cli.Map{"enable": false})
	doc.SetMap("profile", cli.Map{"store-selected": false})
	// A forwarder never matches process rules; skipping process lookups avoids
	// one syscall related probe per connection.
	doc.SetMap("find-process-mode", "off")
	doc.SetMap("log-level", "info")
	doc.SetMap("ipv6", true)
	doc.SetMap("allow-lan", false)

	// Listener: bound to the single outbound, so no rules are needed.
	listener := inbound.Fields.Clone()
	listener["proxy"] = proxyName
	doc.Append("listeners", listener)

	if outbound != nil {
		proxy := outbound.Fields.Clone()
		proxy["name"] = outbound.Name
		doc.Append("proxies", proxy)
	}

	raw, err := doc.Marshal()
	if err != nil {
		return nil, err
	}
	name, _ := listener["name"].(string)
	outboundType := ""
	if outbound != nil {
		outboundType = outbound.Type
	}
	return &Entry{
		Name:         name,
		Type:         inbound.Type,
		OutboundType: outboundType,
		Raw:          doc,
		config:       raw,
	}, nil
}
