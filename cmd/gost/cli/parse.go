package cli

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	M "github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/log"
)

// inboundSchemes maps URL schemes to the mihomo listener type.
var inboundSchemes = map[string]string{
	"socks5h":     "socks",
	"socks5":      "socks",
	"socks":       "socks",
	"http":        "http",
	"https":       "http",
	"mixed":       "mixed",
	"shadowsocks": "shadowsocks",
	"ss":          "shadowsocks",
	"snell":       "snell",
	"vmess":       "vmess",
	"vless":       "vless",
	"trojan":      "trojan",
	"anytls":      "anytls",
	"hysteria2":   "hysteria2",
	"hy2":         "hysteria2",
	"tuic":        "tuic",
	"shadowquic":  "shadowquic",
	"mieru":       "mieru",
	"sdku":        "sudoku",
	"sudo":        "sudoku",
	"trusttunnel": "trusttunnel",
	"tunnel":      "tunnel",
}

// socksLikeInbound are the inbound types that understand SOCKS style targets.
var socksLikeInbound = map[string]bool{
	"socks": true,
	"mixed": true,
	"http":  true,
}

// ParseInbound parses a -L argument, which may be a URL or a YAML fragment.
// ReadFragment resolves a value that may be prefixed with @ to read the
// fragment from a file.
func ReadFragment(value string) (string, error) {
	if !strings.HasPrefix(value, "@") {
		return value, nil
	}
	path := strings.TrimPrefix(value, "@")
	buf, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("can not read fragment file %s: %w", path, err)
	}
	return string(buf), nil
}

// ParseInbound parses a -L argument, which may be a URL or a YAML fragment.
func ParseInbound(value string) (*Inbound, error) {
	fragment, err := ReadFragment(value)
	if err != nil {
		return nil, err
	}
	if LooksLikeURL(fragment) {
		return parseInboundURL(fragment)
	}
	return parseInboundYAML(fragment)
}

// ParseOutbound parses a -F argument, which may be a URL or a YAML fragment.
func ParseOutbound(value string) (*Outbound, error) {
	fragment, err := ReadFragment(value)
	if err != nil {
		return nil, err
	}
	if LooksLikeURL(fragment) {
		return parseOutboundURL(fragment)
	}
	return parseOutboundYAML(fragment)
}

// LooksLikeURL reports whether the value is a single line URL.
func LooksLikeURL(value string) bool {
	scheme, _, found := strings.Cut(value, "://")
	if !found || strings.ContainsAny(value, "\r\n") {
		return false
	}
	if scheme == "" {
		return false
	}
	for _, r := range scheme {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func parseInboundURL(value string) (*Inbound, error) {
	link, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(link.Scheme)
	typ, known := inboundSchemes[scheme]
	if !known {
		// Any other scheme is passed through as the listener type; the decoder
		// reports unsupported types with the full field list.
		typ = scheme
	}
	host := link.Hostname()
	if host == "" {
		// A URL without a host is the common way to write "listen on all
		// interfaces"; the port still comes from the authority.
		if link.Port() == "" {
			return nil, fmt.Errorf("%s url: missing listen address and port", scheme)
		}
		host = "0.0.0.0"
	}
	port := link.Port()
	if port == "" {
		return nil, fmt.Errorf("%s url: missing port", scheme)
	}
	fields := Map{
		"type":   typ,
		"listen": host,
		"port":   port,
		"name":   "inbound",
	}
	if socksLikeInbound[typ] {
		// UDP relay is enabled by default, matching the "just works" goal;
		// users can disable it with ?udp=false.
		fields["udp"] = true
	}
	if scheme == "https" {
		fields["tls"] = true
	}
	if user := link.User; user != nil {
		password, _ := user.Password()
		fields["users"] = []Map{{
			"username": user.Username(),
			"password": password,
		}}
	}
	// Query parameters share the names of the configuration fields, with dots
	// for nested values.
	applyQuery(fields, link.Query(), "inbound")
	return &Inbound{Type: typ, Fields: fields}, nil
}

func parseOutboundURL(value string) (*Outbound, error) {
	value = strings.TrimSpace(value)
	scheme, body, _ := strings.Cut(value, "://")
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "vmess":
		if proxy, err := parseVmessLink(value); err == nil {
			return finishOutbound(scheme, proxy)
		} else if !strings.Contains(body, "@") {
			return nil, err
		}
		// otherwise fall through to the regular URL form (VMessAEAD style)
	case "ssr":
		return parseSSRLink(value)
	}
	link, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	typ := outboundType(scheme)
	fields := Map{}
	if err := fillOutboundFields(typ, scheme, link, fields); err != nil {
		return nil, err
	}
	return finishOutbound(typ, fields)
}

// outboundType maps a URL scheme to the mihomo outbound type.
func outboundType(scheme string) string {
	switch scheme {
	case "socks5h", "socks5", "socks":
		return "socks5"
	case "https":
		return "http"
	case "hy2", "hysteria2":
		return "hysteria2"
	case "ss":
		return "ss"
	default:
		return scheme
	}
}

// finishOutbound fills the proxy name and the type, then validates the
// fragment with the regular proxy decoder.
func finishOutbound(typ string, fields Map) (*Outbound, error) {
	fields["type"] = typ
	name, _ := fields["name"].(string)
	if name == "" {
		name = generatedOutboundName(typ, fields)
		fields["name"] = name
	}
	if err := validateProxy(fields); err != nil {
		return nil, err
	}
	return &Outbound{Type: typ, Name: name, Fields: fields}, nil
}

// fillOutboundFields applies the fixed URL mapping rules for an outbound.
func fillOutboundFields(typ, scheme string, link *url.URL, fields Map) error {
	host := link.Hostname()
	if host == "" {
		return fmt.Errorf("%s url: missing server address", scheme)
	}
	port := link.Port()
	if typ != "wireguard" && port == "" {
		return fmt.Errorf("%s url: missing port", scheme)
	}
	fields["server"] = host
	if port != "" {
		fields["port"] = port
	}

	user := link.User
	switch typ {
	case "ss":
		err := fillShadowsocks(link, user, fields)
		if err != nil {
			return err
		}
	case "socks5", "http":
		if user != nil {
			fields["username"] = user.Username()
			password, _ := user.Password()
			fields["password"] = password
		}
	case "trojan", "anytls", "hysteria2", "trusttunnel":
		if user != nil {
			password := user.Username()
			if p, ok := user.Password(); ok {
				password = p
			}
			fields["password"] = password
		}
	case "vless":
		if user != nil {
			// vless identifies the user by uuid, never by a password
			fields["uuid"] = user.Username()
		}
	case "vmess", "tuic":
		if user != nil {
			fields["uuid"] = user.Username()
			if p, ok := user.Password(); ok {
				fields["password"] = p
			}
		}
	case "shadowquic", "mieru":
		if user != nil {
			fields["username"] = user.Username()
			if p, ok := user.Password(); ok {
				fields["password"] = p
			}
		}
	case "snell":
		if user != nil {
			fields["psk"] = user.Username()
		}
	case "ssh":
		if user != nil {
			fields["username"] = user.Username()
			if p, ok := user.Password(); ok {
				fields["password"] = p
			}
		}
	case "wireguard":
		if user != nil {
			fields["private-key"] = user.Username()
		}
		if link.Port() == "" {
			fields["port"] = 51820
		}
	case "sudoku":
		if user != nil {
			fields["key"] = user.Username()
		}
	default:
		// A generic rule for every other type: a single userinfo value is a
		// password, "user:pass" fills username and password.
		if user != nil {
			if p, ok := user.Password(); ok {
				fields["username"] = user.Username()
				fields["password"] = p
			} else {
				fields["password"] = user.Username()
			}
		}
	}

	if typ == "http" && scheme == "https" {
		fields["tls"] = true
	}
	query := url.Values{}
	for key, values := range link.Query() {
		query[strings.ToLower(key)] = values
	}
	applyShareLinkAliases(typ, fields, query)
	return applyQuery(fields, query, typ)
}

// queryAliases maps query names used by common share links to the matching
// configuration field. The configuration names always win; the alias is only a
// convenience for links copied from other tools.
var queryAliases = map[string]map[string]string{
	"trojan": {
		"allowinsecure":  "skip-cert-verify",
		"fp":             "client-fingerprint",
		"security":       "tls",
		"type":           "network",
		"serviceName":    "grpc-opts.grpc-service-name",
		"host":           "ws-opts.headers.Host",
		"path":           "ws-opts.path",
		"pcs":            "fingerprint",
	},
	"vless": {
		"allowinsecure":  "skip-cert-verify",
		"fp":             "client-fingerprint",
		"security":       "tls",
		"type":           "network",
		"serviceName":    "grpc-opts.grpc-service-name",
		"host":           "ws-opts.headers.Host",
		"path":           "ws-opts.path",
		"pbk":            "reality-opts.public-key",
		"sid":            "reality-opts.short-id",
		"pcs":            "fingerprint",
		"packetencoding": "packet-encoding",
	},
	"vmess": {
		"allowinsecure":  "skip-cert-verify",
		"fp":             "client-fingerprint",
		"security":       "tls",
		"type":           "network",
		"serviceName":    "grpc-opts.grpc-service-name",
		"host":           "ws-opts.headers.Host",
		"path":           "ws-opts.path",
		"pcs":            "fingerprint",
		"packetencoding": "packet-encoding",
	},
	"hysteria2": {
		"auth":          "password",
		"peer":          "sni",
		"insecure":      "skip-cert-verify",
		"hop_interval":  "hop-interval",
		"pinSHA256":     "fingerprint",
		"obfs-password": "obfs-password",
	},
	"hysteria": {
		"auth":      "auth-str",
		"peer":      "sni",
		"insecure":  "skip-cert-verify",
		"upmbps":    "up",
		"downmbps":  "down",
		"obfsParam": "obfs",
	},
	"tuic": {
		"congestion_control": "congestion-controller",
		"udp_relay_mode":     "udp-relay-mode",
		"disable_sni":        "disable-sni",
		"allow_insecure":     "skip-cert-verify",
		"allowinsecure":      "skip-cert-verify",
	},
	"anytls": {
		"allowinsecure": "skip-cert-verify",
		"peer":          "sni",
		"insecure":      "skip-cert-verify",
	},
}

// applyShareLinkAliases rewrites well known share link parameters into the
// configuration field names, in place. Configuration names take precedence:
// when both are present the configuration name wins.
func applyShareLinkAliases(typ string, fields Map, query url.Values) {
	aliases := queryAliases[typ]
	// tls is a boolean derived from security=tls|reality.
	if security := strings.ToLower(query.Get("security")); security != "" {
		switch security {
		case "tls", "reality":
			if _, exist := fields["tls"]; !exist {
				fields["tls"] = true
			}
		}
		delete(query, "security")
	}
	// "type" means the transport for these protocols. Some values used by share
	// links do not match mihomo's transport names.
	if typ == "vless" || typ == "vmess" || typ == "trojan" {
		if network := transportName(strings.ToLower(query.Get("type"))); network != "" {
			if _, exist := fields["network"]; !exist {
				fields["network"] = network
			}
		}
		delete(query, "type")
	}
	names := make([]string, 0, len(aliases))
	for name := range aliases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		target := aliases[name]
		name = strings.ToLower(name)
		values, exist := query[name]
		if !exist || len(values) == 0 {
			continue
		}
		if target == "tls" || target == "network" {
			delete(query, name)
			continue
		}
		// The configuration name wins only when it points at the same field.
		if existsField(fields, target) {
			delete(query, name)
			continue
		}
		applyField(fields, strings.Split(target, "."), values)
		delete(query, name)
	}
}

// transportName maps share link transport names to mihomo transport names.
func transportName(name string) string {
	switch name {
	case "http":
		return "h2"
	case "tcp":
		return ""
	default:
		return name
	}
}

func existsField(fields Map, path string) bool {
	cur := fields
	parts := strings.Split(path, ".")
	for i, key := range parts {
		value, ok := cur[key]
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			return true
		}
		next, ok := value.(Map)
		if !ok {
			return false
		}
		cur = next
	}
	return false
}

func lastPathSegment(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

// fillShadowsocks fills cipher/password and the SIP002 plugin parameter.func fillShadowsocks(link *url.URL, user *url.Userinfo, fields Map) error {
	if user == nil {
		return errors.New("ss url: missing cipher:password")
	}
	cipher := user.Username()
	password, ok := user.Password()
	if !ok {
		// userinfo may be base64 encoded cipher:password as a whole
		decoded, err := decodeBase64Any(user.Username())
		if err != nil {
			return fmt.Errorf("ss url: invalid userinfo: %w", err)
		}
		cipher, password, ok = strings.Cut(decoded, ":")
		if !ok {
			return errors.New("ss url: userinfo must be cipher:password")
		}
	}
	if cipher == "" || password == "" {
		return errors.New("ss url: cipher and password are required")
	}
	fields["cipher"] = cipher
	fields["password"] = password
	fields["udp"] = true
	if plugin := link.Query().Get("plugin"); plugin != "" {
		pluginName, opts, _ := strings.Cut(plugin, ";")
		extractSIP002Plugin(pluginName, opts, fields)
	}
	return nil
}

// extractSIP002Plugin converts the SIP002 plugin string into plugin-opts.
func extractSIP002Plugin(name, opts string, fields Map) {
	param := map[string]string{}
	for _, item := range strings.Split(opts, ";") {
		k, v, _ := strings.Cut(item, "=")
		param[strings.ToLower(k)] = v
	}
	switch {
	case strings.Contains(name, "obfs"):
		fields["plugin"] = "obfs"
		pluginOpts := Map{}
		if v := param["obfs"]; v != "" {
			pluginOpts["mode"] = v
		}
		if v := firstNonEmpty(param["obfs-host"], param["host"]); v != "" {
			pluginOpts["host"] = v
		}
		fields["plugin-opts"] = pluginOpts
	case strings.Contains(name, "v2ray-plugin"):
		fields["plugin"] = "v2ray-plugin"
		pluginOpts := Map{}
		if v := firstNonEmpty(param["mode"], param["obfs"]); v != "" {
			pluginOpts["mode"] = v
		}
		if v := firstNonEmpty(param["host"], param["obfs-host"]); v != "" {
			pluginOpts["host"] = v
		}
		if v := param["path"]; v != "" {
			pluginOpts["path"] = v
		}
		if strings.Contains(opts, "tls") {
			pluginOpts["tls"] = true
		}
		fields["plugin-opts"] = pluginOpts
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseVmessLink parses the V2RayN base64 JSON share link.
func parseVmessLink(value string) (Map, error) {
	_, body, _ := strings.Cut(value, "://")
	if i := strings.IndexAny(body, "#?"); i >= 0 {
		body = body[:i]
	}
	decoded, err := decodeBase64Any(body)
	if err != nil {
		return nil, fmt.Errorf("vmess share link: %w", err)
	}
	values := map[string]any{}
	if err := json.Unmarshal([]byte(decoded), &values); err != nil {
		return nil, fmt.Errorf("vmess share link json: %w", err)
	}
	fields := Map{"type": "vmess", "udp": true}
	if v, ok := values["v"].(string); ok {
		_ = v
	}
	setString := func(key, value string) {
		if value != "" {
			fields[key] = value
		}
	}
	setString("server", jsonString(values, "add"))
	setPort := func(key string, v any) {
		switch value := v.(type) {
		case string:
			if value != "" {
				fields[key] = value
			}
		case float64:
			fields[key] = int(value)
		}
	}
	setPort("port", values["port"])
	setString("uuid", jsonString(values, "id"))
	fields["alterId"] = 0
	if v, ok := values["aid"]; ok {
		fields["alterId"] = v
	}
	fields["cipher"] = "auto"
	if v := jsonString(values, "scy"); v != "" {
		fields["cipher"] = v
	}
	if v := jsonString(values, "sni"); v != "" {
		fields["servername"] = v
	}
	network := strings.ToLower(jsonString(values, "net"))
	if jsonString(values, "type") == "http" {
		network = "http"
	} else if network == "http" {
		network = "h2"
	}
	if network != "" {
		fields["network"] = network
	}
	tls := strings.ToLower(jsonString(values, "tls"))
	if strings.HasSuffix(tls, "tls") || tls == "reality" {
		fields["tls"] = true
	}
	if alpn := jsonString(values, "alpn"); alpn != "" {
		fields["alpn"] = strings.Split(alpn, ",")
	}
	if jsonString(values, "allowInsecure") != "" && jsonString(values, "allowInsecure") != "0" {
		fields["skip-cert-verify"] = true
	}
	switch network {
	case "ws", "httpupgrade":
		wsOpts := Map{"path": "/"}
		if v := jsonString(values, "path"); v != "" {
			wsOpts["path"] = v
		}
		headers := Map{}
		if v := jsonString(values, "host"); v != "" {
			headers["Host"] = v
		}
		wsOpts["headers"] = headers
		fields["ws-opts"] = wsOpts
	case "grpc":
		fields["grpc-opts"] = Map{"grpc-service-name": jsonString(values, "path")}
	case "h2":
		h2Opts := Map{"path": "/"}
		if v := jsonString(values, "path"); v != "" {
			h2Opts["path"] = v
		}
		if v := jsonString(values, "host"); v != "" {
			h2Opts["host"] = []string{v}
		}
		fields["h2-opts"] = h2Opts
	case "http":
		httpOpts := Map{"path": []string{"/"}}
		if v := jsonString(values, "path"); v != "" {
			httpOpts["path"] = []string{v}
		}
		if v := jsonString(values, "host"); v != "" {
			httpOpts["headers"] = Map{"Host": []string{v}}
		}
		fields["http-opts"] = httpOpts
	}
	if name := jsonString(values, "ps"); name != "" {
		fields["name"] = name
	}
	return fields, nil
}

func jsonString(values map[string]any, key string) string {
	if v, ok := values[key].(string); ok {
		return v
	}
	return ""
}

// parseSSRLink parses the base64 SSR share link.
func parseSSRLink(value string) (*Outbound, error) {
	_, body, _ := strings.Cut(value, "://")
	decoded, err := decodeBase64Any(body)
	if err != nil {
		return nil, fmt.Errorf("ssr share link: %w", err)
	}
	before, after, _ := strings.Cut(decoded, "/?")
	parts := strings.Split(before, ":")
	if len(parts) != 6 {
		return nil, errors.New("ssr share link: invalid payload")
	}
	query, err := url.ParseQuery(strings.ReplaceAll(strings.ReplaceAll(after, "+", "-"), "/", "_"))
	if err != nil {
		return nil, fmt.Errorf("ssr share link: %w", err)
	}
	decodeParam := func(key string) string {
		v, err := decodeURLBase64(query.Get(key))
		if err != nil {
			return ""
		}
		return v
	}
	fields := Map{
		"type":     "ssr",
		"server":   parts[0],
		"port":     parts[1],
		"protocol": parts[2],
		"cipher":   parts[3],
		"obfs":     parts[4],
		"password": decodeParamValue(parts[5]),
		"udp":      true,
	}
	if v := decodeParam("obfsparam"); v != "" {
		fields["obfs-param"] = v
	}
	if v := decodeParam("protoparam"); v != "" {
		fields["protocol-param"] = v
	}
	if v := decodeParam("remarks"); v != "" {
		fields["name"] = v
	}
	return finishOutbound("ssr", fields)
}

// decodeParamValue decodes a URL-safe base64 value that may be unpadded.
func decodeParamValue(value string) string {
	decoded, err := decodeURLBase64(value)
	if err != nil {
		return value
	}
	return decoded
}

func decodeURLBase64(value string) (string, error) {
	return decodeBase64Any(value)
}

// decodeBase64Any decodes standard or URL-safe base64, padded or not.
func decodeBase64Any(value string) (string, error) {
	value = strings.TrimSpace(value)
	candidates := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range candidates {
		decoded, err := enc.DecodeString(value)
		if err == nil {
			return string(decoded), nil
		}
		lastErr = err
	}
	return "", lastErr
}

// applyQuery merges URL query parameters into the fragment. Nested values use
// dots, for example ws-opts.path=/ws. Unknown keys are reported and ignored.
func applyQuery(fields Map, query url.Values, kind string) error {
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys) // deterministic list building and warning order
	for _, key := range keys {
		values := query[key]
		if len(values) == 0 {
			continue
		}
		path := strings.Split(key, ".")
		if err := applyField(fields, path, values); err != nil {
			log.Warnln("mhm gost: ignoring %s option %q: %s", kind, key, err.Error())
		}
	}
	return nil
}

// applyField stores a value at the dotted path inside the fragment. Repeated
// parameters become a list.
func applyField(fields Map, path []string, values []string) error {
	cur := fields
	for i, key := range path {
		if i == len(path)-1 {
			if existing, ok := cur[key]; ok {
				// repeated parameters become a list
				switch v := existing.(type) {
				case []string:
					cur[key] = append(v, values...)
				default:
					cur[key] = append([]string{fmt.Sprint(existing)}, values...)
				}
				continue
			}
			if len(values) == 1 {
				cur[key] = coerce(values[0])
			} else {
				list := make([]string, len(values))
				copy(list, values)
				cur[key] = list
			}
			continue
		}
		next, ok := cur[key].(Map)
		if !ok {
			next = Map{}
			cur[key] = next
		}
		cur = next
	}
	return nil
}

// coerce converts a query string into the type the configuration decoders
// expect: bools stay bools, integer strings stay integers, comma separated
// values become lists.
func coerce(value string) any {
	return Coerce(value)
}

// parseInboundYAML merges a YAML fragment with the defaults of its listener
// type.
func parseInboundYAML(fragment string) (*Inbound, error) {
	raw, err := unmarshalFragment(fragment)
	if err != nil {
		return nil, err
	}
	typ, ok := mapString(raw, "type")
	if !ok || typ == "" {
		return nil, errors.New("yaml fragment: missing type")
	}
	// Generated names: the assembler needs a name to bind the listener to the
	// single outbound and to verify the listener after loading.
	if _, exist := raw["name"]; !exist {
		raw["name"] = "inbound"
	}
	// Unknown keys are reported and dropped before the defaults are applied, so
	// a default is never mistaken for a user supplied value.
	merged := FilterKeys(Map(raw), InboundFieldNames(typ), "inbound", typ)
	merged = MergeDefaults(inboundDefaultsOf(typ), merged)
	if err := validateInbound(merged); err != nil {
		return nil, err
	}
	return &Inbound{Type: typ, Fields: merged}, nil
}

func inboundDefaultsOf(typ string) Map {
	if defaults, ok := inboundDefaults[typ]; ok {
		return defaults
	}
	return Map{}
}

// parseOutboundYAML merges a YAML fragment with the defaults of its type and
// validates it with the regular proxy decoder.
func parseOutboundYAML(fragment string) (*Outbound, error) {
	raw, err := unmarshalFragment(fragment)
	if err != nil {
		return nil, err
	}
	typ, ok := mapString(raw, "type")
	if !ok || typ == "" {
		return nil, errors.New("yaml fragment: missing type")
	}
	merged := Map(raw).Clone()
	if _, exist := merged["name"]; !exist {
		merged["name"] = generatedOutboundName(typ, merged)
	}
	if _, ok := merged["udp"]; !ok && outboundUDPDefault(typ) {
		merged["udp"] = true
	}
	merged = FilterKeys(merged, OutboundFieldNames(typ), "outbound", typ)
	return finishOutbound(typ, merged)
}

// generatedOutboundName returns a stable name for a fragment without one, and
// the proxy name used by the generated configuration.
func generatedOutboundName(typ string, fields Map) string {
	if name, ok := fields["name"].(string); ok && name != "" {
		return name
	}
	server, _ := fields["server"].(string)
	if server == "" {
		return "gost-" + typ
	}
	return fmt.Sprintf("gost-%s-%s", typ, server)
}

func mapString(m map[string]any, key string) (string, bool) {
	v, ok := m[key].(string)
	return v, ok
}

func unmarshalFragment(fragment string) (map[string]any, error) {
	out := map[string]any{}
	if err := M.Unmarshal([]byte(fragment), &out); err != nil {
		return nil, fmt.Errorf("yaml fragment: %w", err)
	}
	if out == nil {
		return nil, errors.New("yaml fragment is empty")
	}
	return out, nil
}

// MergeDefaults merges fragment values over a defaults map.
func MergeDefaults(defaults, fragment Map) Map {
	out := defaults.Clone()
	for k, v := range fragment {
		out[k] = v
	}
	return out
}
