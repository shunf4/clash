package config

import (
	"container/list"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/maps"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	P "github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	SNIFF "github.com/metacubex/mihomo/component/sniffer"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/dns/netparam"
	L "github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	T "github.com/metacubex/mihomo/tunnel"

	orderedmap "github.com/wk8/go-ordered-map/v2"
	"gopkg.in/yaml.v3"
)

// General config
type General struct {
	Inbound
	Controller
	Mode                    T.TunnelMode `json:"mode"`
	UnifiedDelay            bool
	LogLevel                log.LogLevel      `json:"log-level"`
	DelayTestUrl            string            `json:"delay-test-url"`
	IPv6                    bool              `json:"ipv6"`
	Interface               string            `json:"interface-name"`
	RoutingMark             int               `json:"-"`
	GeoXUrl                 GeoXUrl           `json:"geox-url"`
	GeoAutoUpdate           bool              `json:"geo-auto-update"`
	GeoUpdateInterval       int               `json:"geo-update-interval"`
	GeodataMode             bool              `json:"geodata-mode"`
	GeodataLoader           string            `json:"geodata-loader"`
	GeositeMatcher          string            `json:"geosite-matcher"`
	TCPConcurrent           bool              `json:"tcp-concurrent"`
	FindProcessMode         P.FindProcessMode `json:"find-process-mode"`
	Sniffing                bool              `json:"sniffing"`
	EBpf                    EBpf              `json:"-"`
	GlobalClientFingerprint string            `json:"global-client-fingerprint"`
	GlobalUA                string            `json:"global-ua"`
}

// Inbound config
type Inbound struct {
	Port              int            `json:"port"`
	SocksPort         int            `json:"socks-port"`
	RedirPort         int            `json:"redir-port"`
	TProxyPort        int            `json:"tproxy-port"`
	MixedPort         int            `json:"mixed-port"`
	Tun               LC.Tun         `json:"tun"`
	TuicServer        LC.TuicServer  `json:"tuic-server"`
	ShadowSocksConfig string         `json:"ss-config"`
	VmessConfig       string         `json:"vmess-config"`
	Authentication    []string       `json:"authentication"`
	SkipAuthPrefixes  []netip.Prefix `json:"skip-auth-prefixes"`
	LanAllowedIPs     []netip.Prefix `json:"lan-allowed-ips"`
	LanDisAllowedIPs  []netip.Prefix `json:"lan-disallowed-ips"`
	AllowLan          bool           `json:"allow-lan"`
	BindAddress       string         `json:"bind-address"`
	InboundTfo        bool           `json:"inbound-tfo"`
	InboundMPTCP      bool           `json:"inbound-mptcp"`
}

// Controller config
type Controller struct {
	ExternalController    string `json:"-"`
	ExternalControllerTLS string `json:"-"`
	ExternalUI            string `json:"-"`
	Secret                string `json:"-"`
}

// NTP config
type NTP struct {
	Enable        bool   `yaml:"enable"`
	Server        string `yaml:"server"`
	Port          int    `yaml:"port"`
	Interval      int    `yaml:"interval"`
	DialerProxy   string `yaml:"dialer-proxy"`
	WriteToSystem bool   `yaml:"write-to-system"`
}

// DNS config
type DNS struct {
	Enable                bool             `yaml:"enable"`
	PreferH3              bool             `yaml:"prefer-h3"`
	IPv6                  bool             `yaml:"ipv6"`
	IPv6Timeout           uint             `yaml:"ipv6-timeout"`
	NameServer            []dns.NameServer `yaml:"nameserver"`
	Fallback              []dns.NameServer `yaml:"fallback"`
	FallbackFilter        FallbackFilter   `yaml:"fallback-filter"`
	Listen                string           `yaml:"listen"`
	EnhancedMode          C.DNSMode        `yaml:"enhanced-mode"`
	DefaultNameserver     []dns.NameServer `yaml:"default-nameserver"`
	CacheAlgorithm        string           `yaml:"cache-algorithm"`
	FakeIPRange           *fakeip.Pool
	Hosts                 *trie.DomainTrie[resolver.HostValue]
	NameServerPolicy      *orderedmap.OrderedMap[string, []dns.NameServer]
	ProxyServerNameserver []dns.NameServer
}

// FallbackFilter config
type FallbackFilter struct {
	GeoIP     bool                   `yaml:"geoip"`
	GeoIPCode string                 `yaml:"geoip-code"`
	IPCIDR    []netip.Prefix         `yaml:"ipcidr"`
	Domain    []string               `yaml:"domain"`
	GeoSite   []router.DomainMatcher `yaml:"geosite"`
}

// Profile config
type Profile struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}

type TLS struct {
	Certificate     string   `yaml:"certificate"`
	PrivateKey      string   `yaml:"private-key"`
	CustomTrustCert []string `yaml:"custom-certifactes"`
}

// IPTables config
type IPTables struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	InboundInterface string   `yaml:"inbound-interface" json:"inbound-interface"`
	Bypass           []string `yaml:"bypass" json:"bypass"`
}

type Sniffer struct {
	Enable          bool
	Sniffers        map[snifferTypes.Type]SNIFF.SnifferConfig
	ForceDomain     *trie.DomainSet
	SkipDomain      *trie.DomainSet
	ForceDnsMapping bool
	ParsePureIp     bool
}

// Experimental config
type Experimental struct {
	Fingerprints     []string `yaml:"fingerprints"`
	QUICGoDisableGSO bool     `yaml:"quic-go-disable-gso"`
	QUICGoDisableECN bool     `yaml:"quic-go-disable-ecn"`
}

// Config is mihomo config manager
type Config struct {
	General                                 *General
	IPTables                                *IPTables
	NTP                                     *NTP
	DNS                                     *DNS
	Experimental                            *Experimental
	Hosts                                   *trie.DomainTrie[resolver.HostValue]
	HostsDialIPDirectlyTrie                 *trie.DomainTrie[bool]
	Profile                                 *Profile
	Rules                                   []C.Rule
	SubRules                                map[string][]C.Rule
	Users                                   []auth.AuthUser
	Proxies                                 map[string]C.Proxy
	Listeners                               map[string]C.InboundListener
	Providers                               map[string]providerTypes.ProxyProvider
	RuleProviders                           map[string]providerTypes.RuleProvider
	Tunnels                                 []LC.Tunnel
	Reverses                                []T.ReverseConf
	ReverseSeeAsErrorIfDisconnectInMillisec int
	ReverseStopAfterErrorRetryCount         int
	ReverseEnableOnAndroidTypeTransports    []int
	T.Clashray
	Sniffer *Sniffer
	TLS     *TLS
}

type RawNTP struct {
	Enable        bool   `yaml:"enable"`
	Server        string `yaml:"server"`
	ServerPort    int    `yaml:"server-port"`
	Interval      int    `yaml:"interval"`
	DialerProxy   string `yaml:"dialer-proxy"`
	WriteToSystem bool   `yaml:"write-to-system"`
}

type RawDNS struct {
	Enable                bool                                `yaml:"enable" json:"enable"`
	PreferH3              bool                                `yaml:"prefer-h3" json:"prefer-h3"`
	IPv6                  bool                                `yaml:"ipv6" json:"ipv6"`
	IPv6Timeout           uint                                `yaml:"ipv6-timeout" json:"ipv6-timeout"`
	UseHosts              bool                                `yaml:"use-hosts" json:"use-hosts"`
	NameServer            []string                            `yaml:"nameserver" json:"nameserver"`
	Fallback              []string                            `yaml:"fallback" json:"fallback"`
	FallbackFilter        RawFallbackFilter                   `yaml:"fallback-filter" json:"fallback-filter"`
	Listen                string                              `yaml:"listen" json:"listen"`
	EnhancedMode          C.DNSMode                           `yaml:"enhanced-mode" json:"enhanced-mode"`
	FakeIPRange           string                              `yaml:"fake-ip-range" json:"fake-ip-range"`
	FakeIPFilter          []string                            `yaml:"fake-ip-filter" json:"fake-ip-filter"`
	DefaultNameserver     []string                            `yaml:"default-nameserver" json:"default-nameserver"`
	CacheAlgorithm        string                              `yaml:"cache-algorithm" json:"cache-algorithm"`
	NameServerPolicy      *orderedmap.OrderedMap[string, any] `yaml:"nameserver-policy" json:"nameserver-policy"`
	ProxyServerNameserver []string                            `yaml:"proxy-server-nameserver" json:"proxy-server-nameserver"`
}

type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip" json:"geoip"`
	GeoIPCode string   `yaml:"geoip-code" json:"geoip-code"`
	IPCIDR    []string `yaml:"ipcidr" json:"ipcidr"`
	Domain    []string `yaml:"domain" json:"domain"`
	GeoSite   []string `yaml:"geosite" json:"geosite"`
}

type RawClashForAndroid struct {
	AppendSystemDNS   bool   `yaml:"append-system-dns" json:"append-system-dns"`
	UiSubtitlePattern string `yaml:"ui-subtitle-pattern" json:"ui-subtitle-pattern"`
}

type RawTun struct {
	Enable              bool       `yaml:"enable" json:"enable"`
	Device              string     `yaml:"device" json:"device"`
	Stack               C.TUNStack `yaml:"stack" json:"stack"`
	DNSHijack           []string   `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool       `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool       `yaml:"auto-detect-interface"`
	RedirectToTun       []string   `yaml:"-" json:"-"`

	MTU        uint32 `yaml:"mtu" json:"mtu,omitempty"`
	GSO        bool   `yaml:"gso" json:"gso,omitempty"`
	GSOMaxSize uint32 `yaml:"gso-max-size" json:"gso-max-size,omitempty"`
	//Inet4Address           []netip.Prefix `yaml:"inet4-address" json:"inet4_address,omitempty"`
	Inet6Address             []netip.Prefix `yaml:"inet6-address" json:"inet6_address,omitempty"`
	StrictRoute              bool           `yaml:"strict-route" json:"strict_route,omitempty"`
	Inet4RouteAddress        []netip.Prefix `yaml:"inet4-route-address" json:"inet4_route_address,omitempty"`
	Inet6RouteAddress        []netip.Prefix `yaml:"inet6-route-address" json:"inet6_route_address,omitempty"`
	Inet4RouteExcludeAddress []netip.Prefix `yaml:"inet4-route-exclude-address" json:"inet4_route_exclude_address,omitempty"`
	Inet6RouteExcludeAddress []netip.Prefix `yaml:"inet6-route-exclude-address" json:"inet6_route_exclude_address,omitempty"`
	IncludeInterface         []string       `yaml:"include-interface" json:"include-interface,omitempty"`
	ExcludeInterface         []string       `yaml:"exclude-interface" json:"exclude-interface,omitempty"`
	IncludeUID               []uint32       `yaml:"include-uid" json:"include_uid,omitempty"`
	IncludeUIDRange          []string       `yaml:"include-uid-range" json:"include_uid_range,omitempty"`
	ExcludeUID               []uint32       `yaml:"exclude-uid" json:"exclude_uid,omitempty"`
	ExcludeUIDRange          []string       `yaml:"exclude-uid-range" json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser       []int          `yaml:"include-android-user" json:"include_android_user,omitempty"`
	IncludePackage           []string       `yaml:"include-package" json:"include_package,omitempty"`
	ExcludePackage           []string       `yaml:"exclude-package" json:"exclude_package,omitempty"`
	EndpointIndependentNat   bool           `yaml:"endpoint-independent-nat" json:"endpoint_independent_nat,omitempty"`
	UDPTimeout               int64          `yaml:"udp-timeout" json:"udp_timeout,omitempty"`
	FileDescriptor           int            `yaml:"file-descriptor" json:"file-descriptor"`
}

type RawTuicServer struct {
	Enable                bool              `yaml:"enable" json:"enable"`
	Listen                string            `yaml:"listen" json:"listen"`
	Token                 []string          `yaml:"token" json:"token"`
	Users                 map[string]string `yaml:"users" json:"users,omitempty"`
	Certificate           string            `yaml:"certificate" json:"certificate"`
	PrivateKey            string            `yaml:"private-key" json:"private-key"`
	CongestionController  string            `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	MaxIdleTime           int               `yaml:"max-idle-time" json:"max-idle-time,omitempty"`
	AuthenticationTimeout int               `yaml:"authentication-timeout" json:"authentication-timeout,omitempty"`
	ALPN                  []string          `yaml:"alpn" json:"alpn,omitempty"`
	MaxUdpRelayPacketSize int               `yaml:"max-udp-relay-packet-size" json:"max-udp-relay-packet-size,omitempty"`
	CWND                  int               `yaml:"cwnd" json:"cwnd,omitempty"`
}

type RawConfig struct {
	Port                    int               `yaml:"port" json:"port"`
	RedirPort               int               `yaml:"redir-port" json:"redir-port"`
	SocksPort               int               `yaml:"socks-port" json:"socks-port"`
	TProxyPort              int               `yaml:"tproxy-port" json:"tproxy-port"`
	MixedPort               int               `yaml:"mixed-port" json:"mixed-port"`
	ShadowSocksConfig       string            `yaml:"ss-config"`
	VmessConfig             string            `yaml:"vmess-config"`
	InboundTfo              bool              `yaml:"inbound-tfo"`
	InboundMPTCP            bool              `yaml:"inbound-mptcp"`
	Authentication          []string          `yaml:"authentication" json:"authentication"`
	SkipAuthPrefixes        []netip.Prefix    `yaml:"skip-auth-prefixes"`
	LanAllowedIPs           []netip.Prefix    `yaml:"lan-allowed-ips"`
	LanDisAllowedIPs        []netip.Prefix    `yaml:"lan-disallowed-ips"`
	AllowLan                bool              `yaml:"allow-lan" json:"allow-lan"`
	BindAddress             string            `yaml:"bind-address" json:"bind-address"`
	Mode                    T.TunnelMode      `yaml:"mode" json:"mode"`
	UnifiedDelay            bool              `yaml:"unified-delay" json:"unified-delay"`
	LogLevel                log.LogLevel      `yaml:"log-level" json:"log-level"`
	DelayTestUrl            string            `yaml:"delay-test-url"`
	IPv6                    bool              `yaml:"ipv6" json:"ipv6"`
	ExternalController      string            `yaml:"external-controller"`
	ExternalControllerTLS   string            `yaml:"external-controller-tls"`
	ExternalUI              string            `yaml:"external-ui"`
	ExternalUIURL           string            `yaml:"external-ui-url" json:"external-ui-url"`
	ExternalUIName          string            `yaml:"external-ui-name" json:"external-ui-name"`
	Secret                  string            `yaml:"secret"`
	Interface               string            `yaml:"interface-name"`
	RoutingMark             int               `yaml:"routing-mark"`
	Tunnels                 []LC.Tunnel       `yaml:"tunnels"`
	GeoAutoUpdate           bool              `yaml:"geo-auto-update" json:"geo-auto-update"`
	GeoUpdateInterval       int               `yaml:"geo-update-interval" json:"geo-update-interval"`
	GeodataMode             bool              `yaml:"geodata-mode" json:"geodata-mode"`
	GeodataLoader           string            `yaml:"geodata-loader" json:"geodata-loader"`
	GeositeMatcher          string            `yaml:"geosite-matcher" json:"geosite-matcher"`
	TCPConcurrent           bool              `yaml:"tcp-concurrent" json:"tcp-concurrent"`
	FindProcessMode         P.FindProcessMode `yaml:"find-process-mode" json:"find-process-mode"`
	GlobalClientFingerprint string            `yaml:"global-client-fingerprint"`
	GlobalUA                string            `yaml:"global-ua"`
	KeepAliveInterval       int               `yaml:"keep-alive-interval"`

	Sniffer       RawSniffer                `yaml:"sniffer" json:"sniffer"`
	ProxyProvider map[string]map[string]any `yaml:"proxy-providers"`
	RuleProvider  map[string]map[string]any `yaml:"rule-providers"`
	Hosts         map[string]any            `yaml:"hosts" json:"hosts"`
	NTP           RawNTP                    `yaml:"ntp" json:"ntp"`
	DNS           RawDNS                    `yaml:"dns" json:"dns"`
	Tun           RawTun                    `yaml:"tun"`
	TuicServer    RawTuicServer             `yaml:"tuic-server"`
	EBpf          EBpf                      `yaml:"ebpf"`
	IPTables      IPTables                  `yaml:"iptables"`
	Experimental  Experimental              `yaml:"experimental"`
	Profile       Profile                   `yaml:"profile"`
	GeoXUrl       GeoXUrl                   `yaml:"geox-url"`
	Proxy         []map[string]any          `yaml:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups"`
	Rule          []string                  `yaml:"rules"`
	SubRules      map[string][]string       `yaml:"sub-rules"`
	RawTLS        TLS                       `yaml:"tls"`
	Listeners     []map[string]any          `yaml:"listeners"`
	Reverses      []T.ReverseConf           `yaml:"reverses"`

	ReverseStopAfterErrorRetryCount         int   `yaml:"reverse-stop-after-error-retry-count"`
	ReverseSeeAsErrorIfDisconnectInMillisec int   `yaml:"reverse-see-as-error-if-disconnect-in-millisec"`
	ReverseEnableOnAndroidTypeTransports    []int `yaml:"reverse-enable-on-android-type-transports"`

	ClashForAndroid RawClashForAndroid `yaml:"clash-for-android" json:"clash-for-android"`

	ClashrayNetCurrAsPublisher                  string                     `yaml:"clashray-net-curr-as-publisher"`
	ClashrayNetCurrIsAsVisitor                  bool                       `yaml:"clashray-net-curr-is-as-visitor"`
	ClashrayNetVisitorTunnelNoHostsNorListening bool                       `yaml:"clashray-net-visitor-tunnel-no-hosts-nor-listening"`
	ClashrayNetHTTPRedirectLocalListenAddr      string                     `yaml:"clashray-net-http-redirect-local-listen-addr"`
	ClashrayNetHTTPRedirectLocalListenPort      uint16                     `yaml:"clashray-net-http-redirect-local-listen-port-yes-i-dont-want-80"`
	ClashrayTestLocalListenAddr                 string                     `yaml:"clashray-test-local-listen-addr"`
	ClashrayTestLocalListenPort                 uint16                     `yaml:"clashray-test-local-listen-port-yes-i-dont-want-80"`
	ClashraySendLocalListenAddr                 string                     `yaml:"clashray-send-local-listen-addr"`
	ClashraySendLocalListenPort                 uint16                     `yaml:"clashray-send-local-listen-port-yes-i-dont-want-80"`
	ClashraySendDir                             string                     `yaml:"clashray-send-dir"`
	ClashraySendHistoryMaxSize                  uint32                     `yaml:"clashray-send-history-max-size"`
	ClashrayNetPublishers                       []T.ClashrayNetPublisher   `yaml:"clashray-net-publishers"`
	ClashrayHTTPRedirectMap                     map[string]string          `yaml:"clashray-http-redirect-map"`
	ClashraySendCORSAllowedOrigins              []string                   `yaml:"clashray-send-cors-allowed-origins"`
	ClashrayCurrPublisherAppendServices         []string                   `yaml:"clashray-curr-publisher-append-services"`
	ClashrayCurrPublisherAppendLanContacts      []map[string]interface{}   `yaml:"clashray-curr-publisher-append-lan-contacts"`
	ClashrayCurrPublisherAppendReverseContacts  []T.ClashrayReverseContact `yaml:"clashray-curr-publisher-append-reverse-contacts"`
}

type GeoXUrl struct {
	GeoIp   string `yaml:"geoip" json:"geoip"`
	Mmdb    string `yaml:"mmdb" json:"mmdb"`
	GeoSite string `yaml:"geosite" json:"geosite"`
}

type RawSniffer struct {
	Enable          bool                         `yaml:"enable" json:"enable"`
	OverrideDest    bool                         `yaml:"override-destination" json:"override-destination"`
	Sniffing        []string                     `yaml:"sniffing" json:"sniffing"`
	ForceDomain     []string                     `yaml:"force-domain" json:"force-domain"`
	SkipDomain      []string                     `yaml:"skip-domain" json:"skip-domain"`
	Ports           []string                     `yaml:"port-whitelist" json:"port-whitelist"`
	ForceDnsMapping bool                         `yaml:"force-dns-mapping" json:"force-dns-mapping"`
	ParsePureIp     bool                         `yaml:"parse-pure-ip" json:"parse-pure-ip"`
	Sniff           map[string]RawSniffingConfig `yaml:"sniff" json:"sniff"`
}

type RawSniffingConfig struct {
	Ports        []string `yaml:"ports" json:"ports"`
	OverrideDest *bool    `yaml:"override-destination" json:"override-destination"`
}

// EBpf config
type EBpf struct {
	RedirectToTun []string `yaml:"redirect-to-tun" json:"redirect-to-tun"`
	AutoRedir     []string `yaml:"auto-redir" json:"auto-redir"`
}

var (
	GroupsList             = list.New()
	ProxiesList            = list.New()
	ParsingProxiesCallback func(groupsList *list.List, proxiesList *list.List)
)

// Parse config
func Parse(buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}

	return ParseRawConfig(rawCfg)
}

func UnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	// config with default value
	rawCfg := &RawConfig{
		AllowLan:          false,
		BindAddress:       "*",
		LanAllowedIPs:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		IPv6:              true,
		Mode:              T.Rule,
		GeoAutoUpdate:     false,
		GeoUpdateInterval: 24,
		GeodataMode:       C.GeodataMode,
		GeodataLoader:     "memconservative",
		UnifiedDelay:      false,
		Authentication:    []string{},
		LogLevel:          log.INFO,
		DelayTestUrl:      "",
		Hosts:             map[string]any{},
		Rule:              []string{},
		Proxy:             []map[string]any{},
		ProxyGroup:        []map[string]any{},
		TCPConcurrent:     false,
		FindProcessMode:   P.FindProcessStrict,
		GlobalUA:          "clash.meta",
		Tun: RawTun{
			Enable:              false,
			Device:              "",
			Stack:               C.TunGvisor,
			DNSHijack:           []string{"0.0.0.0:53"}, // default hijack all dns query
			AutoRoute:           true,
			AutoDetectInterface: true,
			Inet6Address:        []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		},
		TuicServer: RawTuicServer{
			Enable:                false,
			Token:                 nil,
			Users:                 nil,
			Certificate:           "",
			PrivateKey:            "",
			Listen:                "",
			CongestionController:  "",
			MaxIdleTime:           15000,
			AuthenticationTimeout: 1000,
			ALPN:                  []string{"h3"},
			MaxUdpRelayPacketSize: 1500,
		},
		EBpf: EBpf{
			RedirectToTun: []string{},
			AutoRedir:     []string{},
		},
		IPTables: IPTables{
			Enable:           false,
			InboundInterface: "lo",
			Bypass:           []string{},
		},
		NTP: RawNTP{
			Enable:        false,
			WriteToSystem: false,
			Server:        "time.apple.com",
			ServerPort:    123,
			Interval:      30,
		},
		DNS: RawDNS{
			Enable:       false,
			IPv6:         false,
			UseHosts:     true,
			IPv6Timeout:  100,
			EnhancedMode: C.DNSMapping,
			FakeIPRange:  "198.18.0.1/16",
			FallbackFilter: RawFallbackFilter{
				GeoIP:     true,
				GeoIPCode: "CN",
				IPCIDR:    []string{},
				GeoSite:   []string{},
			},
			DefaultNameserver: []string{
				"114.114.114.114",
				"223.5.5.5",
				"8.8.8.8",
				"1.0.0.1",
			},
			NameServer: []string{
				"https://doh.pub/dns-query",
				"tls://223.5.5.5:853",
			},
			FakeIPFilter: []string{
				"dns.msftnsci.com",
				"www.msftnsci.com",
				"www.msftconnecttest.com",
			},
		},
		Sniffer: RawSniffer{
			Enable:          false,
			Sniffing:        []string{},
			ForceDomain:     []string{},
			SkipDomain:      []string{},
			Ports:           []string{},
			ForceDnsMapping: true,
			ParsePureIp:     true,
			OverrideDest:    true,
		},
		Profile: Profile{
			StoreSelected: true,
		},
		GeoXUrl: GeoXUrl{
			Mmdb:    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
			GeoIp:   "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
			GeoSite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
		},
		ExternalUIURL: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",

		ClashrayNetCurrAsPublisher: "",
		ClashrayNetCurrIsAsVisitor: false,
		// ClashrayNetVisitorTunnelNoHostsNorListening: false,
		ClashrayNetVisitorTunnelNoHostsNorListening: true,
	}

	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}

	return rawCfg, nil
}

func ParseRawConfig(rawCfg *RawConfig) (*Config, error) {
	config := &Config{}
	log.Infoln("Start initial configuration in progress") //Segment finished in xxm
	startTime := time.Now()

	////// shunf4 mod: clashray-net: start

	config.Clashray.ClashrayNetCurrAsPublisher = rawCfg.ClashrayNetCurrAsPublisher
	config.Clashray.ClashrayNetCurrIsAsVisitor = rawCfg.ClashrayNetCurrIsAsVisitor
	config.Clashray.ClashrayNetVisitorTunnelNoHostsNorListening = rawCfg.ClashrayNetVisitorTunnelNoHostsNorListening
	config.Clashray.ClashrayNetHTTPRedirectLocalListenAddr = rawCfg.ClashrayNetHTTPRedirectLocalListenAddr
	config.Clashray.ClashrayNetHTTPRedirectLocalListenPort = rawCfg.ClashrayNetHTTPRedirectLocalListenPort
	config.Clashray.ClashrayTestLocalListenAddr = rawCfg.ClashrayTestLocalListenAddr
	config.Clashray.ClashrayTestLocalListenPort = rawCfg.ClashrayTestLocalListenPort
	config.Clashray.ClashraySendLocalListenAddr = rawCfg.ClashraySendLocalListenAddr
	config.Clashray.ClashraySendLocalListenPort = rawCfg.ClashraySendLocalListenPort
	config.Clashray.ClashrayHTTPRedirectMap = rawCfg.ClashrayHTTPRedirectMap
	config.Clashray.ClashraySendCORSAllowedOrigins = rawCfg.ClashraySendCORSAllowedOrigins
	config.Clashray.ClashraySendDir = rawCfg.ClashraySendDir
	config.Clashray.ClashraySendHistoryMaxSize = rawCfg.ClashraySendHistoryMaxSize
	config.Clashray.ClashrayNetPublishers = rawCfg.ClashrayNetPublishers
	pMap := make(map[string]*T.ClashrayNetPublisher)
	config.Clashray.ClashrayNetPublishersMap = pMap

	if rawCfg.Rule == nil {
		rawCfg.Rule = make([]string, 0)
	}
	if rawCfg.SubRules == nil {
		rawCfg.SubRules = make(map[string][]string)
	}
	if rawCfg.ProxyGroup == nil {
		rawCfg.ProxyGroup = make([]map[string]any, 0)
	}
	if rawCfg.Proxy == nil {
		rawCfg.Proxy = make([]map[string]any, 0)
	}
	if rawCfg.Listeners == nil {
		rawCfg.Listeners = make([]map[string]any, 0)
	}
	if rawCfg.Reverses == nil {
		rawCfg.Reverses = make([]T.ReverseConf, 0)
	}
	if rawCfg.Hosts == nil {
		rawCfg.Hosts = make(map[string]any)
	}
	if config.Clashray.ClashrayHTTPRedirectMap == nil {
		config.Clashray.ClashrayHTTPRedirectMap = make(map[string]string)
	}
	if config.Clashray.ClashraySendCORSAllowedOrigins == nil {
		config.Clashray.ClashraySendCORSAllowedOrigins = make([]string, 0)
	}

	publisherEverMatched := false

	for i := range config.Clashray.ClashrayNetPublishers {
		p := &config.Clashray.ClashrayNetPublishers[i]
		if p.Name == "" {
			return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers[%d].Name is empty", i)
		}
		if _, found := pMap[p.Name]; found {
			return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers Name=%s is duplicate", p.Name)
		}

		pMap[p.Name] = p
		if p.ContactProxyGroupFallbackInterval < 5 || p.ContactProxyGroupFallbackInterval > 86400*1000*7 {
			return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s): ContactProxyGroupFallbackInterval is invalid (%d)", p.Name, p.ContactProxyGroupFallbackInterval)
		}

		{
			isCurrentPublisher := false
			if config.Clashray.ClashrayNetCurrAsPublisher == p.Name {
				isCurrentPublisher = true
			}
			if isCurrentPublisher {
				p.LanContacts = append(p.LanContacts, rawCfg.ClashrayCurrPublisherAppendLanContacts...)
				p.ReverseContacts = append(p.ReverseContacts, rawCfg.ClashrayCurrPublisherAppendReverseContacts...)
				p.Services = append(p.Services, rawCfg.ClashrayCurrPublisherAppendServices...)
			}
		}

		currContactProxyGroupName := "clashray-net-" + p.Name + "-contact"
		payloadConnNonLocalRuleName := "clashray-net-" + p.Name + "-payload-conn-non-local-rule"
		payloadConnNonLocalFinalRuleName := "clashray-net-" + p.Name + "-payload-conn-non-local-rule-final"
		payloadConnLocalOnlyRuleName := "clashray-net-" + p.Name + "-payload-conn-local-only-rule"
		payloadConnLocalAndNonLocalFinalRuleName := "clashray-net-" + p.Name + "-payload-conn-local-and-non-local-rule-final"

		visitorNotPublisherProxies := []map[string]any{}
		visitorNotPublisherProxyGroups := []map[string]any{}

		var visitorNotPublisherContactProxyGroup map[string]interface{}
		visitorNotPublisherContactProxyGroup = make(map[string]interface{})
		visitorNotPublisherContactProxyGroup["name"] = currContactProxyGroupName
		visitorNotPublisherContactProxyGroup["type"] = "fallback"
		visitorNotPublisherContactProxyGroup["proxies"] = []string{}
		visitorNotPublisherContactProxyGroup["url"] = p.ContactHealthcheckURL
		visitorNotPublisherContactProxyGroup["interval"] = p.ContactProxyGroupFallbackInterval
		visitorNotPublisherContactProxyGroup["lazy"] = p.ContactProxyGroupFallbackIsLazy
		visitorNotPublisherProxyGroups = append(visitorNotPublisherProxyGroups, visitorNotPublisherContactProxyGroup)

		publisherLanContactListeners := []map[string]interface{}{}

		for lci := range p.LanContacts {
			lc := &p.LanContacts[lci]
			// useExistingProxy at the same time means "not listening on the publisher side"
			if useExistingProxy, found := (*lc)["useExistingProxy"]; found {
				if useExistingProxy, convOk := useExistingProxy.(string); convOk {
					currLanContactName := useExistingProxy
					visitorNotPublisherContactProxyGroup["proxies"] = append(visitorNotPublisherContactProxyGroup["proxies"].([]string), currLanContactName)
					continue
				}
			}
			var fullLanContact map[string]interface{}
			if p.LanContactsCommonFields != nil {
				fullLanContact = make(map[string]interface{})
				maps.Copy(fullLanContact, p.LanContactsCommonFields)
				maps.Copy(fullLanContact, *lc)
			} else {
				fullLanContact = *lc
			}
			currLanContactName := "clashray-net-" + p.Name + "-lan-contact-" + strconv.Itoa(lci)
			fullLanContact["name"] = currLanContactName
			visitorNotPublisherProxies = append(visitorNotPublisherProxies, fullLanContact)
			visitorNotPublisherContactProxyGroup["proxies"] = append(visitorNotPublisherContactProxyGroup["proxies"].([]string), currLanContactName)
			{
				currLanContactListenerName := currLanContactName
				currLanContactListener := map[string]interface{}{}
				currLanContactListener["name"] = currLanContactListenerName
				currLanContactListener["rule"] = payloadConnNonLocalFinalRuleName
				switch fullLanContact["type"] {
				case "vmess":
					currLanContactListener["type"] = "vmess"
					currLanContactListener["port"] = fullLanContact["port"]
					if listenValue, ok := fullLanContact["publisherListen"]; ok {
						currLanContactListener["listen"] = listenValue
					} else {
						currLanContactListener["listen"] = fullLanContact["server"]
					}
					users := []map[string]interface{}{}
					user0 := map[string]interface{}{}
					if vmessUsernameValue, ok := fullLanContact["publisherVmessUsername"]; ok {
						user0["username"] = vmessUsernameValue
					} else {
						user0["username"] = "user"
					}
					user0["uuid"] = fullLanContact["uuid"]
					user0["alterId"] = fullLanContact["alterId"]
					users = append(users, user0)
					currLanContactListener["users"] = users
				case "ss":
					currLanContactListener["type"] = "shadowsocks"
					currLanContactListener["port"] = fullLanContact["port"]
					if listenValue, ok := fullLanContact["publisherListen"]; ok {
						currLanContactListener["listen"] = listenValue
					} else {
						currLanContactListener["listen"] = fullLanContact["server"]
					}
					currLanContactListener["cipher"] = fullLanContact["cipher"]
					currLanContactListener["password"] = fullLanContact["password"]
					if udpValue, ok := fullLanContact["udp"]; ok {
						currLanContactListener["udp"] = udpValue
					} else {
						currLanContactListener["udp"] = true
					}
				case "http":
					currLanContactListener["type"] = "http"
					currLanContactListener["port"] = fullLanContact["port"]
					if listenValue, ok := fullLanContact["publisherListen"]; ok {
						currLanContactListener["listen"] = listenValue
					} else {
						currLanContactListener["listen"] = fullLanContact["server"]
					}
				case "socks5":
					currLanContactListener["type"] = "http"
					currLanContactListener["port"] = fullLanContact["port"]
					if listenValue, ok := fullLanContact["publisherListen"]; ok {
						currLanContactListener["listen"] = listenValue
					} else {
						currLanContactListener["listen"] = fullLanContact["server"]
					}
					if udpValue, ok := fullLanContact["udp"]; ok {
						currLanContactListener["udp"] = udpValue
					} else {
						currLanContactListener["udp"] = true
					}
				default:
					return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s): LanContacts[%d]: type is invalid (%s)", p.Name, lci, fullLanContact["type"])
				}
				publisherLanContactListeners = append(publisherLanContactListeners, currLanContactListener)
			}
		}

		publisherReverses := []T.ReverseConf{}
		publisherBridgeConnRules := map[string][]string{}

		for rci := range p.ReverseContacts {
			rc := &p.ReverseContacts[rci]
			publisherBridgeConnRuleName := "clashray-net-" + p.Name + "-bridge-conn-rule-" + strconv.Itoa(rci) + "-" + rc.BridgeConnProxy
			{
				visitorProxy := rc.VisitorProxy
				if visitorProxy == "" {
					visitorProxy = rc.BridgeConnProxy
				}
				visitorNotPublisherContactProxyGroup["proxies"] = append(visitorNotPublisherContactProxyGroup["proxies"].([]string), visitorProxy)
			}
			{
				publisherBridgeConnRules[publisherBridgeConnRuleName] = []string{
					"MATCH," + rc.BridgeConnProxy,
				}

				publisherReverses = append(publisherReverses, T.ReverseConf{
					ReverseIdentDomain: rc.ReverseIdentDomain,
					BridgeConnSubRule:  publisherBridgeConnRuleName,
					PayloadConnSubRule: payloadConnNonLocalFinalRuleName,
					WorkerNum:          rc.WorkerNum,
					RetryDelayMillisec: rc.RetryDelayMillisec,
				})
			}
		}

		visitorNotPublisherPayloadConnHTTPRedirectRules := []string{}
		publisherAlsoVisitorPayloadConnHTTPRedirectRules := []string{}
		visitorNotPublisherHTTPRedirectMap := map[string]string{}
		publisherAlsoVisitorHTTPRedirectMap := map[string]string{}

		visitorNotPublisherPayloadConnSvcRules := []string{}
		publisherNonLocalPayloadConnSvcRules := []string{}
		publisherNonLocalPayloadConnSvcRules_pre1 := []string{}
		publisherLocalOnlyPayloadConnSvcRules := []string{}
		publisherLocalOnlyPayloadConnSvcRules_pre1 := []string{}
		visitorNotPublisherVisitorTunnelListeners := []map[string]interface{}{}
		publisherVisitorTunnelListeners := []map[string]interface{}{}
		visitorNotPublisherHosts := map[string]interface{}{}
		publisherAlsoVisitorHosts := map[string]interface{}{}

		visitorNotPublisherCORSAllowed := []string{}
		publisherCORSAllowed := []string{}

		for si := range p.Services {
			s := p.Services[si]
			var err error
			isLocalOnly := false
			s, isLocalOnly = strings.CutPrefix(s, "LOCAL-ONLY,")
			sParts := strings.Split(s, ",")
			for spi := range sParts {
				sParts[spi] = strings.TrimSpace(sParts[spi])
			}
			if len(sParts) < 3 {
				return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services: bad service line, len(sParts) %d less than 3", p.Name, len(sParts))
			}
			sMatchCond := sParts[0]
			sHost := strings.TrimPrefix(sParts[1], ".")
			if sHost == "" {
				return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad service line, sHost is empty", p.Name, si)
			}
			var sHostWildcard string
			if sMatchCond == "DOMAIN-SUFFIX" {
				sHostWildcard = "+." + sHost
			} else if sMatchCond == "DOMAIN" {
				sHostWildcard = sHost
			} else {
				return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad service line, invalid sMatchCond %s", p.Name, si, sMatchCond)
			}
			sRealDestProxy := sParts[2]
			if sRealDestProxy == "" {
				return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad service line, sRealDestProxy is empty", p.Name, si)
			}
			if sRealDestProxy != "BLANKET-FORWARD" && len(sParts) < 4 {
				return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services: bad service line, len(sParts) %d less than 4", p.Name, len(sParts))
			}
			var sRealDestHost string
			var sRealDestPort string
			if sRealDestProxy == "BLANKET-FORWARD" {
				sRealDestHost = "BLANKET-FORWARD"
				sRealDestPort = "BLANKET-FORWARD"
				if isLocalOnly {
					return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services: bad service line, conflicts: LOCAL-ONLY and BLANKET-FORWARD", p.Name)
				} else {
					visitorNotPublisherPayloadConnSvcRules = append(visitorNotPublisherPayloadConnSvcRules, fmt.Sprintf("%s,%s,%s", sMatchCond, sHost, currContactProxyGroupName))
				}
			} else {
				sRealDestAddr := sParts[3]
				if sRealDestAddr == "" {
					return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad service line, sRealDestAddr is empty", p.Name, si)
				}

				sRealDestHost, sRealDestPort, err = net.SplitHostPort(sRealDestAddr)
				if err != nil {
					sRealDestHost = sRealDestAddr
					sRealDestPort = ""
				} else {
					sRealDestPort = ":::" + sRealDestPort
				}

				if isLocalOnly {
					publisherLocalOnlyPayloadConnSvcRules = append(publisherLocalOnlyPayloadConnSvcRules, fmt.Sprintf("%s,%s,%s", sMatchCond, sHost, sRealDestProxy+":::"+sRealDestHost+sRealDestPort))
				} else {
					visitorNotPublisherPayloadConnSvcRules = append(visitorNotPublisherPayloadConnSvcRules, fmt.Sprintf("%s,%s,%s", sMatchCond, sHost, currContactProxyGroupName))
					publisherNonLocalPayloadConnSvcRules = append(publisherNonLocalPayloadConnSvcRules, fmt.Sprintf("%s,%s,%s", sMatchCond, sHost, sRealDestProxy+":::"+sRealDestHost+sRealDestPort))
				}

				if sRealDestProxy == "INTERNAL-HTTP" && sRealDestHost == "CLASHRAY-SEND" {
					if !isLocalOnly {
						visitorNotPublisherCORSAllowed = append(visitorNotPublisherCORSAllowed, sHost)
						if sMatchCond == "DOMAIN-SUFFIX" {
							visitorNotPublisherCORSAllowed = append(visitorNotPublisherCORSAllowed, "*."+sHost)
						}
					}
					publisherCORSAllowed = append(publisherCORSAllowed, sHost)
					if sMatchCond == "DOMAIN-SUFFIX" {
						publisherCORSAllowed = append(publisherCORSAllowed, "*."+sHost)
					}
				}
			}

			visitorNotPublisherVisitorTunnelDedup := map[string]bool{}
			publisherVisitorTunnelDedup := map[string]bool{}
			for spi := 4; spi < len(sParts); spi++ {
				opt := sParts[spi]
				if vt, ok := strings.CutPrefix(opt, "visitortunnel="); ok {
					vtParts := strings.Split(vt, ":::")
					for vtpi := range vtParts {
						vtParts[vtpi] = strings.TrimSpace(vtParts[vtpi])
					}
					if len(vtParts) < 2 {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad visitortunnel option, len(vtParts) %d < 2", p.Name, si, len(vtParts))
					}
					vtHostWildcard := vtParts[0]
					if vtHostWildcard == "." {
						vtHostWildcard = sHostWildcard
					}
					if vtHostWildcard == "" {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad visitortunnel option, vtHostWildcard is empty", p.Name, si)
					}
					vtListenHost := vtParts[1]
					if vtListenHost == "" {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad visitortunnel option, vtListenHost is empty", p.Name, si)
					}
					var vtListenPortStr string
					var vtListenPortRaw uint64
					var vtListenPort uint16
					if len(vtParts) >= 3 {
						vtListenPortStr = vtParts[2]
						if vtListenPortStr == "" {
							return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad visitortunnel option, vtListenPortStr is empty", p.Name, si)
						}
						vtListenPortRaw, err = strconv.ParseUint(vtListenPortStr, 10, 16)
						if err != nil {
							return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad visitortunnel option, parsing vtListenPortStr %s: %v", p.Name, si, vtListenPortStr, err)
						}
						vtListenPort = uint16(vtListenPortRaw)
						vtListenPortStr = strconv.FormatInt(int64(vtListenPort), 10)
					}

					tunnelName := "clashray-net-" + p.Name + "-svc-" + strconv.Itoa(si) + "-tunnel-" + strconv.Itoa(spi-4)

					if vtListenPort > 0 {
						if !isLocalOnly {
							if _, found := visitorNotPublisherVisitorTunnelDedup[vtListenHost+":"+vtListenPortStr]; !found {
								currListener := make(map[string]interface{})
								visitorNotPublisherVisitorTunnelListeners = append(visitorNotPublisherVisitorTunnelListeners, currListener)
								currListener["name"] = tunnelName
								currListener["type"] = "tunnel"
								currListener["listen"] = vtListenHost
								currListener["port"] = vtListenPort
								currListener["network"] = []string{"tcp"}
								currListener["target"] = sHost + ":" + vtListenPortStr
								currListener["rule"] = payloadConnNonLocalFinalRuleName

								visitorNotPublisherVisitorTunnelDedup[vtListenHost+":"+vtListenPortStr] = true
							}
						}

						if _, found := publisherVisitorTunnelDedup[vtListenHost+":"+vtListenPortStr]; !found {
							currListener := make(map[string]interface{})
							publisherVisitorTunnelListeners = append(publisherVisitorTunnelListeners, currListener)
							currListener["name"] = tunnelName
							currListener["type"] = "tunnel"
							currListener["listen"] = vtListenHost
							currListener["port"] = vtListenPort
							currListener["network"] = []string{"tcp"}
							currListener["target"] = sHost + ":" + vtListenPortStr
							currListener["rule"] = payloadConnLocalAndNonLocalFinalRuleName

							publisherVisitorTunnelDedup[vtListenHost+":"+vtListenPortStr] = true
						}
					}

					if !isLocalOnly {
						visitorNotPublisherHosts[vtHostWildcard] = vtListenHost
					}
					publisherAlsoVisitorHosts[vtHostWildcard] = vtListenHost

					if vtListenPort > 0 {
						if !isLocalOnly {
							visitorNotPublisherPayloadConnSvcRules = append(
								visitorNotPublisherPayloadConnSvcRules,
								"AND,((IP-CIDR,"+vtListenHost+"/32,no-resolve),(DST-PORT,"+vtListenPortStr+")),"+currContactProxyGroupName+":::"+sHost,
							)
						}
						if sRealDestHost != "BLANKET-FORWARD" {
							if !isLocalOnly {
								publisherNonLocalPayloadConnSvcRules = append(
									publisherNonLocalPayloadConnSvcRules,
									"AND,((IP-CIDR,"+vtListenHost+"/32,no-resolve),(DST-PORT,"+vtListenPortStr+")),"+sRealDestProxy+":::"+sRealDestHost+sRealDestPort,
								)
							} else {
								publisherLocalOnlyPayloadConnSvcRules = append(
									publisherLocalOnlyPayloadConnSvcRules,
									"AND,((IP-CIDR,"+vtListenHost+"/32,no-resolve),(DST-PORT,"+vtListenPortStr+")),"+sRealDestProxy+":::"+sRealDestHost+sRealDestPort,
								)
							}
						}
					} else {
						if !isLocalOnly {
							visitorNotPublisherPayloadConnSvcRules = append(
								visitorNotPublisherPayloadConnSvcRules,
								"IP-CIDR,"+vtListenHost+"/32,"+currContactProxyGroupName+":::"+sHost+",no-resolve",
							)
						}
						if sRealDestHost != "BLANKET-FORWARD" {
							if !isLocalOnly {
								publisherNonLocalPayloadConnSvcRules = append(
									publisherNonLocalPayloadConnSvcRules,
									"IP-CIDR,"+vtListenHost+"/32,"+sRealDestProxy+":::"+sRealDestHost+sRealDestPort+",no-resolve",
								)
							} else {
								publisherLocalOnlyPayloadConnSvcRules = append(
									publisherLocalOnlyPayloadConnSvcRules,
									"IP-CIDR,"+vtListenHost+"/32,"+sRealDestProxy+":::"+sRealDestHost+sRealDestPort+",no-resolve",
								)
							}
						}
					}

					if len(vtParts) >= 4 {
						if len(vtParts) < 4 {
							return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad visitortunnel-httpredirect option, len(vtParts) %d < 4", p.Name, si, len(vtParts))
						}
						httpRedirectHost, cutOk := strings.CutPrefix(vtParts[3], "httpredirect=")
						if !cutOk {
							return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad visitortunnel-httpredirect option, vtParts[3] %s expected starting with httpredirect=", p.Name, si, vtParts[3])
						}

						httpRedirectTarget := vtListenHost
						if vtListenPort > 0 {
							httpRedirectTarget += ":" + vtListenPortStr
						} else if sRealDestPort != "" {
							// TODO: use sRealDestPort?
						}

						if !isLocalOnly {
							visitorNotPublisherHTTPRedirectMap[httpRedirectHost] = httpRedirectTarget
							visitorNotPublisherPayloadConnHTTPRedirectRules = append(visitorNotPublisherPayloadConnHTTPRedirectRules, fmt.Sprintf("%s,%s,%s", "DOMAIN", httpRedirectHost, "INTERNAL-HTTP:::CLASHRAY-HTTP-REDIRECT"))
						}

						publisherAlsoVisitorHTTPRedirectMap[httpRedirectHost] = httpRedirectTarget
						publisherAlsoVisitorPayloadConnHTTPRedirectRules = append(publisherAlsoVisitorPayloadConnHTTPRedirectRules, fmt.Sprintf("%s,%s,%s", "DOMAIN", httpRedirectHost, "INTERNAL-HTTP:::CLASHRAY-HTTP-REDIRECT"))
					}
				}
				if pm, ok := strings.CutPrefix(opt, "portmap="); ok {
					pmParts := strings.Split(pm, "->")
					for pmpi := range pmParts {
						pmParts[pmpi] = strings.TrimSpace(pmParts[pmpi])
					}
					if len(pmParts) < 2 {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad portmap option, len(pmParts) %d < 2", p.Name, si, len(pmParts))
					}
					pmFromPortStr := pmParts[0]
					var pmFromPortRaw uint64
					var pmFromPort uint16
					if pmFromPortStr == "" {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad portmap option, pmFromPortStr is empty", p.Name, si)
					}
					pmFromPortRaw, err = strconv.ParseUint(pmFromPortStr, 10, 16)
					if err != nil {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad portmap option, parsing pmFromPortStr %s: %v", p.Name, si, pmFromPortStr, err)
					}
					pmFromPort = uint16(pmFromPortRaw)
					pmFromPortStr = strconv.FormatInt(int64(pmFromPort), 10)

					pmToPortStr := pmParts[1]
					var pmToPortRaw uint64
					var pmToPort uint16
					if pmToPortStr == "" {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad portmap option, pmToPortStr is empty", p.Name, si)
					}
					pmToPortRaw, err = strconv.ParseUint(pmToPortStr, 10, 16)
					if err != nil {
						return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s).Services[%d]: bad portmap option, parsing pmToPortStr %s: %v", p.Name, si, pmToPortStr, err)
					}
					pmToPort = uint16(pmToPortRaw)
					pmToPortStr = strconv.FormatInt(int64(pmToPort), 10)

					if pmFromPort > 0 && pmToPort > 0 {
						if sRealDestHost != "BLANKET-FORWARD" {
							if isLocalOnly {
								publisherLocalOnlyPayloadConnSvcRules_pre1 = append(
									publisherLocalOnlyPayloadConnSvcRules_pre1,
									fmt.Sprintf("AND,((%s,%s),(DST-PORT,%s)),%s", sMatchCond, sHost, pmFromPortStr, sRealDestProxy+":::"+sRealDestHost+":::"+pmToPortStr),
								)
							} else {
								publisherNonLocalPayloadConnSvcRules_pre1 = append(
									publisherNonLocalPayloadConnSvcRules_pre1,
									fmt.Sprintf("AND,((%s,%s),(DST-PORT,%s)),%s", sMatchCond, sHost, pmFromPortStr, sRealDestProxy+":::"+sRealDestHost+":::"+pmToPortStr),
								)
							}
						}
					}
				}
			}
		}

		if strings.TrimPrefix(p.ContactHealthcheckURL, "http://") == "" {
			return nil, fmt.Errorf("config.Clashray.ClashrayNetPublishers(Name=%s): bad ContactHealthcheckURL: %s", p.Name, p.ContactHealthcheckURL)
		}
		visitorNotPublisherPayloadConnSvcRules = append(visitorNotPublisherPayloadConnSvcRules,
			fmt.Sprintf("%s,%s,%s", "DOMAIN", strings.TrimPrefix(p.ContactHealthcheckURL, "http://"), currContactProxyGroupName),
		)
		if strings.TrimPrefix(p.ContactSendURL, "http://") != "" {
			visitorNotPublisherPayloadConnSvcRules = append(visitorNotPublisherPayloadConnSvcRules,
				fmt.Sprintf("%s,%s,%s", "DOMAIN", strings.TrimPrefix(p.ContactSendURL, "http://"), currContactProxyGroupName),
			)
		}

		publisherNonLocalPayloadConnSvcRules = append(publisherNonLocalPayloadConnSvcRules,
			"DOMAIN,"+strings.TrimPrefix(p.ContactHealthcheckURL, "http://")+",INTERNAL-HTTP:::CLASHRAY-TEST",
		)
		if strings.TrimPrefix(p.ContactSendURL, "http://") != "" {
			publisherNonLocalPayloadConnSvcRules = append(publisherNonLocalPayloadConnSvcRules,
				"DOMAIN,"+strings.TrimPrefix(p.ContactSendURL, "http://")+",INTERNAL-HTTP:::CLASHRAY-SEND",
			)
		}

		// finally mutating config according to current role (publisher and/or visitor)

		isCurrentPublisher := false
		if config.Clashray.ClashrayNetCurrAsPublisher == p.Name {
			isCurrentPublisher = true
			publisherEverMatched = true
		}
		isVisitor := config.Clashray.ClashrayNetCurrIsAsVisitor

		payloadConnNonLocalSubRule := []string{}
		payloadConnLocalOnlySubRule := []string{}
		payloadConnNonLocalFinalSubRule := []string{"SUB-RULE,(NETWORK,tcp)," + payloadConnNonLocalRuleName, "MATCH,REJECT"}
		payloadConnLocalAndNonLocalFinalSubRule := []string{"SUB-RULE,(NETWORK,tcp)," + payloadConnLocalOnlyRuleName, "SUB-RULE,(NETWORK,tcp)," + payloadConnNonLocalRuleName, "MATCH,REJECT"}

		publisherAction := func() {
			maps.Copy(rawCfg.SubRules, publisherBridgeConnRules)

			payloadConnNonLocalSubRule = append(payloadConnNonLocalSubRule,
				publisherNonLocalPayloadConnSvcRules_pre1...,
			)
			payloadConnNonLocalSubRule = append(payloadConnNonLocalSubRule,
				publisherNonLocalPayloadConnSvcRules...,
			)
			payloadConnLocalOnlySubRule = append(payloadConnLocalOnlySubRule,
				publisherLocalOnlyPayloadConnSvcRules_pre1...,
			)
			payloadConnLocalOnlySubRule = append(payloadConnLocalOnlySubRule,
				publisherLocalOnlyPayloadConnSvcRules...,
			)

			rawCfg.Listeners = append(rawCfg.Listeners, publisherLanContactListeners...)
			rawCfg.Reverses = append(rawCfg.Reverses, publisherReverses...)
			rawCfg.ClashraySendCORSAllowedOrigins = append(rawCfg.ClashraySendCORSAllowedOrigins, publisherCORSAllowed...)
			config.Clashray.ClashraySendCORSAllowedOrigins = append(config.Clashray.ClashraySendCORSAllowedOrigins, publisherCORSAllowed...)
		}

		// if isVisitor || isCurrentPublisher {
		addPayloadNonLocalRulesAction := func() {
			rawCfg.SubRules[payloadConnNonLocalRuleName] = payloadConnNonLocalSubRule
			rawCfg.SubRules[payloadConnNonLocalFinalRuleName] = payloadConnNonLocalFinalSubRule
		}

		if isVisitor && !isCurrentPublisher {
			rawCfg.Proxy = append(rawCfg.Proxy, visitorNotPublisherProxies...)
			rawCfg.ProxyGroup = append(rawCfg.ProxyGroup, visitorNotPublisherProxyGroups...)

			payloadConnNonLocalSubRule = append(payloadConnNonLocalSubRule, visitorNotPublisherPayloadConnHTTPRedirectRules...)
			payloadConnNonLocalSubRule = append(payloadConnNonLocalSubRule, visitorNotPublisherPayloadConnSvcRules...)

			addPayloadNonLocalRulesAction()

			rawCfg.Rule = append([]string{"SUB-RULE,(NETWORK,tcp)," + payloadConnNonLocalRuleName}, rawCfg.Rule...)
			maps.Copy(config.Clashray.ClashrayHTTPRedirectMap, visitorNotPublisherHTTPRedirectMap)
			if !config.Clashray.ClashrayNetVisitorTunnelNoHostsNorListening {
				rawCfg.Listeners = append(rawCfg.Listeners, visitorNotPublisherVisitorTunnelListeners...)
				maps.Copy(rawCfg.Hosts, visitorNotPublisherHosts)
			}

			rawCfg.ClashraySendCORSAllowedOrigins = append(rawCfg.ClashraySendCORSAllowedOrigins, visitorNotPublisherCORSAllowed...)
			config.Clashray.ClashraySendCORSAllowedOrigins = append(config.Clashray.ClashraySendCORSAllowedOrigins, visitorNotPublisherCORSAllowed...)
		} else if isVisitor && isCurrentPublisher {
			payloadConnNonLocalSubRule = append(payloadConnNonLocalSubRule, publisherAlsoVisitorPayloadConnHTTPRedirectRules...)
			publisherAction()

			addPayloadNonLocalRulesAction()
			rawCfg.SubRules[payloadConnLocalOnlyRuleName] = payloadConnLocalOnlySubRule
			rawCfg.SubRules[payloadConnLocalAndNonLocalFinalRuleName] = payloadConnLocalAndNonLocalFinalSubRule

			rawCfg.Rule = append([]string{
				"SUB-RULE,(NETWORK,tcp)," + payloadConnLocalOnlyRuleName,
				"SUB-RULE,(NETWORK,tcp)," + payloadConnNonLocalRuleName,
			}, rawCfg.Rule...)
			maps.Copy(config.Clashray.ClashrayHTTPRedirectMap, publisherAlsoVisitorHTTPRedirectMap)
			if !config.Clashray.ClashrayNetVisitorTunnelNoHostsNorListening {
				rawCfg.Listeners = append(rawCfg.Listeners, publisherVisitorTunnelListeners...)
				maps.Copy(rawCfg.Hosts, publisherAlsoVisitorHosts)
			}
		} else if !isVisitor && isCurrentPublisher {
			publisherAction()
			addPayloadNonLocalRulesAction()
		} else if !isVisitor && !isCurrentPublisher {

		}

	}

	if !publisherEverMatched && config.Clashray.ClashrayNetCurrAsPublisher != "" {
		log.Warnln("clashray-net: warn: ClashrayNetCurrAsPublisher [%s] never matched", config.Clashray.ClashrayNetCurrAsPublisher)
	}

	if !config.Clashray.ClashrayNetVisitorTunnelNoHostsNorListening {
		if config.Clashray.ClashrayNetHTTPRedirectLocalListenAddr != "dontListen" {
			httpRedirectListener := make(map[string]interface{})
			rawCfg.Listeners = append(rawCfg.Listeners, httpRedirectListener)
			httpRedirectListener["name"] = "clashray-http-redirect-listener"
			httpRedirectListener["type"] = "tunnel"
			{
				lAddr := "127.0.199.199"
				if config.Clashray.ClashrayNetHTTPRedirectLocalListenAddr != "" {
					lAddr = config.Clashray.ClashrayNetHTTPRedirectLocalListenAddr
				}
				httpRedirectListener["listen"] = lAddr
			}
			{
				lPort := uint16(80)
				if config.Clashray.ClashrayNetHTTPRedirectLocalListenPort != uint16(0) {
					lPort = config.Clashray.ClashrayNetHTTPRedirectLocalListenPort
				}
				httpRedirectListener["port"] = lPort
			}

			httpRedirectListener["network"] = []string{"tcp"}
			httpRedirectListener["target"] = "0.0.0.0" + ":" + "0"
			httpRedirectListener["rule"] = "clashray-http-redirect-rule"

			for httpRedirectHost := range rawCfg.ClashrayHTTPRedirectMap {
				rawCfg.Hosts[httpRedirectHost] = httpRedirectListener["listen"]
			}
		}
	}
	rawCfg.SubRules["clashray-http-redirect-rule"] = []string{
		"MATCH,INTERNAL-HTTP:::CLASHRAY-HTTP-REDIRECT",
	}

	/////////////

	if !config.Clashray.ClashrayNetVisitorTunnelNoHostsNorListening {
		if config.Clashray.ClashrayTestLocalListenAddr != "dontListen" {
			clashrayTestListener := make(map[string]interface{})
			rawCfg.Listeners = append(rawCfg.Listeners, clashrayTestListener)
			clashrayTestListener["name"] = "clashray-test-listener"
			clashrayTestListener["type"] = "tunnel"
			{
				lAddr := "127.0.199.198"
				if config.Clashray.ClashrayTestLocalListenAddr != "" {
					lAddr = config.Clashray.ClashrayTestLocalListenAddr
				}
				clashrayTestListener["listen"] = lAddr
			}
			{
				lPort := uint16(80)
				if config.Clashray.ClashrayTestLocalListenPort != uint16(0) {
					lPort = config.Clashray.ClashrayTestLocalListenPort
				}
				clashrayTestListener["port"] = lPort
			}

			clashrayTestListener["network"] = []string{"tcp"}
			clashrayTestListener["target"] = "0.0.0.0" + ":" + "0"
			clashrayTestListener["rule"] = "clashray-test-rule"

			rawCfg.Hosts["test.clashray.home.arpa"] = clashrayTestListener["listen"]
		}
	}
	rawCfg.SubRules["clashray-test-rule"] = []string{
		"MATCH,INTERNAL-HTTP:::CLASHRAY-TEST",
	}

	/////////////

	if !config.Clashray.ClashrayNetVisitorTunnelNoHostsNorListening {
		if config.Clashray.ClashraySendLocalListenAddr != "dontListen" {
			clashraySendListener := make(map[string]interface{})
			rawCfg.Listeners = append(rawCfg.Listeners, clashraySendListener)
			clashraySendListener["name"] = "clashray-send-listener"
			clashraySendListener["type"] = "tunnel"
			{
				lAddr := "127.0.199.197"
				if config.Clashray.ClashraySendLocalListenAddr != "" {
					lAddr = config.Clashray.ClashraySendLocalListenAddr
				}
				clashraySendListener["listen"] = lAddr
			}
			{
				lPort := uint16(80)
				if config.Clashray.ClashraySendLocalListenPort != uint16(0) {
					lPort = config.Clashray.ClashraySendLocalListenPort
				}
				clashraySendListener["port"] = lPort
			}

			clashraySendListener["network"] = []string{"tcp"}
			clashraySendListener["target"] = "0.0.0.0" + ":" + "0"
			clashraySendListener["rule"] = "clashray-send-rule"

			rawCfg.Hosts["send.clashray.home.arpa"] = clashraySendListener["listen"]
		}
	}
	rawCfg.SubRules["clashray-send-rule"] = []string{
		"MATCH,INTERNAL-HTTP:::CLASHRAY-SEND",
	}

	rawCfg.Rule = append([]string{"DOMAIN-SUFFIX,test.clashray.home.arpa,INTERNAL-HTTP:::CLASHRAY-TEST", "DOMAIN-SUFFIX,send.clashray.home.arpa,INTERNAL-HTTP:::CLASHRAY-SEND"}, rawCfg.Rule...)
	rawCfg.ClashraySendCORSAllowedOrigins = append(rawCfg.ClashraySendCORSAllowedOrigins, "test.clashray.home.arpa")
	config.Clashray.ClashraySendCORSAllowedOrigins = append(config.Clashray.ClashraySendCORSAllowedOrigins, "test.clashray.home.arpa")
	rawCfg.ClashraySendCORSAllowedOrigins = append(rawCfg.ClashraySendCORSAllowedOrigins, "send.clashray.home.arpa")
	config.Clashray.ClashraySendCORSAllowedOrigins = append(config.Clashray.ClashraySendCORSAllowedOrigins, "send.clashray.home.arpa")

	////// shunf4 mod: clashray-net: end

	config.Experimental = &rawCfg.Experimental
	config.Profile = &rawCfg.Profile
	config.IPTables = &rawCfg.IPTables
	config.TLS = &rawCfg.RawTLS

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	if len(config.General.GlobalClientFingerprint) != 0 {
		log.Debugln("GlobalClientFingerprint: %s", config.General.GlobalClientFingerprint)
		tlsC.SetGlobalUtlsClient(config.General.GlobalClientFingerprint)
	}

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	listener, err := parseListeners(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Listeners = listener

	log.Infoln("Geodata Loader mode: %s", geodata.LoaderName())
	log.Infoln("Geosite Matcher implementation: %s", geodata.SiteMatcherName())
	ruleProviders, err := parseRuleProviders(rawCfg)
	if err != nil {
		return nil, err
	}
	config.RuleProviders = ruleProviders

	subRules, err := parseSubRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.SubRules = subRules

	rules, err := parseRules(rawCfg.Rule, proxies, subRules, "rules")
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, hostsDialIPDirectlyTrie, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts
	config.HostsDialIPDirectlyTrie = hostsDialIPDirectlyTrie

	ntpCfg := paresNTP(rawCfg)
	config.NTP = ntpCfg

	dnsCfg, err := parseDNS(rawCfg, hosts, rules, ruleProviders)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	err = parseTun(rawCfg.Tun, config.General)
	if !features.CMFA && err != nil {
		return nil, err
	}

	err = parseTuicServer(rawCfg.TuicServer, config.General)
	if err != nil {
		return nil, err
	}

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Tunnels = rawCfg.Tunnels
	// verify tunnels
	for _, t := range config.Tunnels {
		if len(t.Proxy) > 0 {
			if _, ok := config.Proxies[t.Proxy]; !ok {
				return nil, fmt.Errorf("tunnel proxy %s not found", t.Proxy)
			}
		}
	}

	config.Reverses = rawCfg.Reverses
	config.ReverseStopAfterErrorRetryCount = rawCfg.ReverseStopAfterErrorRetryCount
	config.ReverseSeeAsErrorIfDisconnectInMillisec = rawCfg.ReverseSeeAsErrorIfDisconnectInMillisec
	config.ReverseEnableOnAndroidTypeTransports = rawCfg.ReverseEnableOnAndroidTypeTransports
	for ri := range config.Reverses {
		r := &config.Reverses[ri]
		if r.ReverseIdentDomain == "" {
			return nil, fmt.Errorf("reverse.reverseIdentDomain is empty")
		}
		if r.RetryDelayMillisec == 0 {
			r.RetryDelayMillisec = 3000
		}
		if r.RetryDelayMillisec < 0 {
			return nil, fmt.Errorf("reverse.retryDelayMillisec is invalid")
		}
		if r.WorkerNum == 0 {
			r.WorkerNum = 1
		}
		if r.WorkerNum < 1 || r.WorkerNum > 50 {
			return nil, fmt.Errorf("reverse.workerNum is invalid (should between 1 and 50)")
		}
	}

	config.Sniffer, err = parseSniffer(rawCfg.Sniffer)
	if err != nil {
		return nil, err
	}

	elapsedTime := time.Since(startTime) / time.Millisecond                     // duration in ms
	log.Infoln("Initial configuration complete, total time: %dms", elapsedTime) //Segment finished in xxm

	T.SaveClashCurrRawConfig(yaml.Marshal(rawCfg))

	return config, nil
}

func parseGeneral(cfg *RawConfig) (*General, error) {
	geodata.SetLoader(cfg.GeodataLoader)
	geodata.SetSiteMatcher(cfg.GeositeMatcher)
	C.GeoAutoUpdate = cfg.GeoAutoUpdate
	C.GeoUpdateInterval = cfg.GeoUpdateInterval
	C.GeoIpUrl = cfg.GeoXUrl.GeoIp
	C.GeoSiteUrl = cfg.GeoXUrl.GeoSite
	C.MmdbUrl = cfg.GeoXUrl.Mmdb
	C.GeodataMode = cfg.GeodataMode
	C.UA = cfg.GlobalUA
	if cfg.KeepAliveInterval != 0 {
		N.KeepAliveInterval = time.Duration(cfg.KeepAliveInterval) * time.Second
	}

	ExternalUIPath = cfg.ExternalUI
	// checkout externalUI exist
	if ExternalUIPath != "" {
		ExternalUIPath = C.Path.Resolve(ExternalUIPath)
		if _, err := os.Stat(ExternalUIPath); os.IsNotExist(err) {
			defaultUIpath := path.Join(C.Path.HomeDir(), "ui")
			log.Warnln("external-ui: %s does not exist, creating folder in %s", ExternalUIPath, defaultUIpath)
			if err := os.MkdirAll(defaultUIpath, os.ModePerm); err != nil {
				return nil, err
			}
			ExternalUIPath = defaultUIpath
			cfg.ExternalUI = defaultUIpath
		}
	}
	// checkout UIpath/name exist
	if cfg.ExternalUIName != "" {
		ExternalUIName = cfg.ExternalUIName
	} else {
		ExternalUIFolder = ExternalUIPath
	}
	if cfg.ExternalUIURL != "" {
		ExternalUIURL = cfg.ExternalUIURL
	}

	cfg.Tun.RedirectToTun = cfg.EBpf.RedirectToTun
	return &General{
		Inbound: Inbound{
			Port:              cfg.Port,
			SocksPort:         cfg.SocksPort,
			RedirPort:         cfg.RedirPort,
			TProxyPort:        cfg.TProxyPort,
			MixedPort:         cfg.MixedPort,
			ShadowSocksConfig: cfg.ShadowSocksConfig,
			VmessConfig:       cfg.VmessConfig,
			AllowLan:          cfg.AllowLan,
			SkipAuthPrefixes:  cfg.SkipAuthPrefixes,
			LanAllowedIPs:     cfg.LanAllowedIPs,
			LanDisAllowedIPs:  cfg.LanDisAllowedIPs,
			BindAddress:       cfg.BindAddress,
			InboundTfo:        cfg.InboundTfo,
			InboundMPTCP:      cfg.InboundMPTCP,
		},
		Controller: Controller{
			ExternalController:    cfg.ExternalController,
			ExternalUI:            cfg.ExternalUI,
			Secret:                cfg.Secret,
			ExternalControllerTLS: cfg.ExternalControllerTLS,
		},
		UnifiedDelay:            cfg.UnifiedDelay,
		Mode:                    cfg.Mode,
		LogLevel:                cfg.LogLevel,
		DelayTestUrl:            cfg.DelayTestUrl,
		IPv6:                    cfg.IPv6,
		Interface:               cfg.Interface,
		RoutingMark:             cfg.RoutingMark,
		GeoXUrl:                 cfg.GeoXUrl,
		GeoAutoUpdate:           cfg.GeoAutoUpdate,
		GeoUpdateInterval:       cfg.GeoUpdateInterval,
		GeodataMode:             cfg.GeodataMode,
		GeodataLoader:           cfg.GeodataLoader,
		TCPConcurrent:           cfg.TCPConcurrent,
		FindProcessMode:         cfg.FindProcessMode,
		EBpf:                    cfg.EBpf,
		GlobalClientFingerprint: cfg.GlobalClientFingerprint,
		GlobalUA:                cfg.GlobalUA,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider

	var proxyList []string
	var AllProxies []string
	proxiesList := list.New()
	groupsList := list.New()

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxies["REJECT-DROP"] = adapter.NewProxy(outbound.NewRejectDrop())
	proxies["COMPATIBLE"] = adapter.NewProxy(outbound.NewCompatible())
	proxies["PASS"] = adapter.NewProxy(outbound.NewPass())
	proxies["INTERNAL-HTTP"] = adapter.NewProxy(outbound.NewInternalHTTP(outbound.InternalHTTPOption{Name: "INTERNAL-HTTP"}))
	proxyList = append(proxyList, "DIRECT", "REJECT")

	// parse proxy
	for idx, mapping := range proxiesConfig {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy %d: %w", idx, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		proxyList = append(proxyList, proxy.Name())
		AllProxies = append(AllProxies, proxy.Name())
		proxiesList.PushBack(mapping)
	}

	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		proxyList = append(proxyList, groupName)
		groupsList.PushBack(mapping)
	}

	// check if any loop exists and sort the ProxyGroups
	if err := proxyGroupsDagSort(groupsConfig); err != nil {
		return nil, nil, err
	}

	var AllProviders []string
	// parse and initial providers
	for name, mapping := range providersConfig {
		if name == provider.ReservedName {
			return nil, nil, fmt.Errorf("can not defined a provider called `%s`", provider.ReservedName)
		}

		pd, err := provider.ParseProxyProvider(name, mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}

		providersMap[name] = pd
		AllProviders = append(AllProviders, name)
	}

	// parse proxy group
	for idx, mapping := range groupsConfig {
		group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap, AllProxies, AllProviders)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy group[%d]: %w", idx, err)
		}

		groupName := group.Name()
		if _, exist := proxies[groupName]; exist {
			return nil, nil, fmt.Errorf("proxy group %s: the duplicate name", groupName)
		}

		proxies[groupName] = adapter.NewProxy(group)
	}

	var ps []C.Proxy
	for _, v := range proxyList {
		if proxies[v].Type() == C.Pass {
			continue
		}
		ps = append(ps, proxies[v])
	}
	hc := provider.NewHealthCheck(ps, "", 5000, 0, true, nil)
	pd, _ := provider.NewCompatibleProvider(provider.ReservedName, ps, hc)
	providersMap[provider.ReservedName] = pd

	global := outboundgroup.NewSelector(
		&outboundgroup.GroupCommonOption{
			Name: "GLOBAL",
		},
		[]providerTypes.ProxyProvider{pd},
	)
	proxies["GLOBAL"] = adapter.NewProxy(global)
	ProxiesList = proxiesList
	GroupsList = groupsList
	if ParsingProxiesCallback != nil {
		// refresh tray menu
		go ParsingProxiesCallback(GroupsList, ProxiesList)
	}
	return proxies, providersMap, nil
}

func parseListeners(cfg *RawConfig) (listeners map[string]C.InboundListener, err error) {
	L.ParseListenersStart()
	defer L.ParseListenersEnd()
	listeners = make(map[string]C.InboundListener)
	for index, mapping := range cfg.Listeners {
		listener, err := L.ParseListener(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", index, err)
		}

		if _, exist := mapping[listener.Name()]; exist {
			return nil, fmt.Errorf("listener %s is the duplicate name", listener.Name())
		}

		listeners[listener.Name()] = listener

	}
	return
}

func parseRuleProviders(cfg *RawConfig) (ruleProviders map[string]providerTypes.RuleProvider, err error) {
	ruleProviders = map[string]providerTypes.RuleProvider{}
	// parse rule provider
	for name, mapping := range cfg.RuleProvider {
		rp, err := RP.ParseRuleProvider(name, mapping, R.ParseRule)
		if err != nil {
			return nil, err
		}

		ruleProviders[name] = rp
		RP.SetRuleProvider(rp)
	}
	return
}

func parseSubRules(cfg *RawConfig, proxies map[string]C.Proxy) (subRules map[string][]C.Rule, err error) {
	subRules = map[string][]C.Rule{}
	for name := range cfg.SubRules {
		subRules[name] = make([]C.Rule, 0)
	}
	for name, rawRules := range cfg.SubRules {
		if len(name) == 0 {
			return nil, fmt.Errorf("sub-rule name is empty")
		}
		var rules []C.Rule
		rules, err = parseRules(rawRules, proxies, subRules, fmt.Sprintf("sub-rules[%s]", name))
		if err != nil {
			return nil, err
		}
		subRules[name] = rules
	}

	if err = verifySubRule(subRules); err != nil {
		return nil, err
	}

	return
}

func verifySubRule(subRules map[string][]C.Rule) error {
	for name := range subRules {
		err := verifySubRuleCircularReferences(name, subRules, []string{})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySubRuleCircularReferences(n string, subRules map[string][]C.Rule, arr []string) error {
	isInArray := func(v string, array []string) bool {
		for _, c := range array {
			if v == c {
				return true
			}
		}
		return false
	}

	arr = append(arr, n)
	for i, rule := range subRules[n] {
		if rule.RuleType() == C.SubRules {
			if _, ok := subRules[rule.Adapter()]; !ok {
				return fmt.Errorf("sub-rule[%d:%s] error: [%s] not found", i, n, rule.Adapter())
			}
			if isInArray(rule.Adapter(), arr) {
				arr = append(arr, rule.Adapter())
				return fmt.Errorf("sub-rule error: circular references [%s]", strings.Join(arr, "->"))
			}

			if err := verifySubRuleCircularReferences(rule.Adapter(), subRules, arr); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseRules(rulesConfig []string, proxies map[string]C.Proxy, subRules map[string][]C.Rule, format string) ([]C.Rule, error) {
	var rules []C.Rule

	// parse rules
	for idx, line := range rulesConfig {
		rule := trimArr(strings.Split(line, ","))
		var (
			payload  string
			target   string
			params   []string
			ruleName = strings.ToUpper(rule[0])
		)

		l := len(rule)

		if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" || ruleName == "SUB-RULE" {
			target = rule[l-1]
			payload = strings.Join(rule[1:l-1], ",")
		} else {
			if l < 2 {
				return nil, fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
			}
			if l < 4 {
				rule = append(rule, make([]string, 4-l)...)
			}
			if ruleName == "MATCH" {
				l = 2
			}
			if l >= 3 {
				l = 3
				payload = rule[1]
			}
			target = rule[l-1]
			params = rule[l:]
		}
		targetParts := strings.Split(target, ":::")
		if _, ok := proxies[targetParts[0]]; !ok {
			if ruleName != "SUB-RULE" {
				return nil, fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
			} else if _, ok = subRules[target]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
			}
		}

		params = trimArr(params)
		parsed, parseErr := R.ParseRule(ruleName, payload, target, params, subRules)
		if parseErr != nil {
			return nil, fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, parseErr.Error())
		}

		rules = append(rules, parsed)
	}

	return rules, nil
}

// parseHosts returns a host-ip trie, a host-dialIPDirectly trie, and error.
func parseHosts(cfg *RawConfig) (*trie.DomainTrie[resolver.HostValue], *trie.DomainTrie[bool], error) {
	tree := trie.New[resolver.HostValue]()
	dialIPDirectlyTree := trie.New[bool]()

	// add default hosts
	hostValue, _ := resolver.NewHostValueByIPs(
		[]netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})})
	if err := tree.Insert("localhost", hostValue); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, anyValue := range cfg.Hosts {
			if str, ok := anyValue.(string); ok && str == "lan" {
				if addrs, err := net.InterfaceAddrs(); err != nil {
					log.Errorln("insert lan to host error: %s", err)
				} else {
					ips := make([]netip.Addr, 0)
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
							if ip, err := netip.ParseAddr(ipnet.IP.String()); err == nil {
								ips = append(ips, ip)
							}
						}
					}
					anyValue = ips
				}
			}
			hasDialIPDirectlySuffix := false
			domain, hasDialIPDirectlySuffix = strings.CutSuffix(domain, ",dial-ip-directly")
			if str, ok := anyValue.(string); ok {
				anyValue, hasDialIPDirectlySuffix = strings.CutSuffix(str, ",dial-ip-directly")
			}

			value, err := resolver.NewHostValue(anyValue)
			if err != nil {
				return nil, nil, fmt.Errorf("%s is not a valid value", anyValue)
			}
			if value.IsDomain {
				node := tree.Search(value.Domain)
				for node != nil && node.Data().IsDomain {
					if node.Data().Domain == domain {
						return nil, nil, fmt.Errorf("%s, there is a cycle in domain name mapping", domain)
					}
					node = tree.Search(node.Data().Domain)
				}
			}
			_ = tree.Insert(domain, value)
			_ = dialIPDirectlyTree.Insert(domain, hasDialIPDirectlySuffix)
		}
	}
	tree.Optimize()

	return tree, dialIPDirectlyTree, nil
}

func hostWithDefaultPort(host string, defPort string) (string, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", err
		}
		host = host + ":" + defPort
		if hostname, port, err = net.SplitHostPort(host); err != nil {
			return "", err
		}
	}

	return net.JoinHostPort(hostname, port), nil
}

func batchAddNameservers(nameservers []dns.NameServer, toBeAdded []string, logPrefix string) ([]dns.NameServer, error) {
	for _, n := range toBeAdded {
		addr, err := hostWithDefaultPort(n, "53")
		if err != nil {
			return nil, fmt.Errorf("%s: DNS Nameserver(%s) format error: %s", logPrefix, n, err.Error())
		}
		log.Infoln("%s: Added DNS Nameserver to built-in DNS: %s", logPrefix, addr)
		nameservers = append(
			nameservers,
			dns.NameServer{
				Net:  "", // UDP
				Addr: addr,
			},
		)
	}
	return nameservers, nil
}

func parseNameServer(servers []string, preferH3 bool) ([]dns.NameServer, error) {
	var nameservers []dns.NameServer

	for idx, server := range servers {
		server = parsePureDNSServer(server)
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		proxyName := u.Fragment

		var addr, dnsNetType string
		params := map[string]string{}
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "" // UDP
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp" // TCP
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tcp-tls" // DNS over TLS
		case "https":
			addr, err = hostWithDefaultPort(u.Host, "443")
			if err == nil {
				proxyName = ""
				clearURL := url.URL{Scheme: "https", Host: addr, Path: u.Path, User: u.User}
				addr = clearURL.String()
				dnsNetType = "https" // DNS over HTTPS
				if len(u.Fragment) != 0 {
					for _, s := range strings.Split(u.Fragment, "&") {
						arr := strings.Split(s, "=")
						if len(arr) == 0 {
							continue
						} else if len(arr) == 1 {
							proxyName = arr[0]
						} else if len(arr) == 2 {
							params[arr[0]] = arr[1]
						} else {
							params[arr[0]] = strings.Join(arr[1:], "=")
						}
					}
				}
			}
		case "dhcp":
			addr = u.Host
			dnsNetType = "dhcp" // UDP from DHCP
		case "special":
			dnsNetType = "special"
			switch u.Host {
			case "dynamic-system-resolve-client":
				addr = "localResolveClient"
			case "dynamic-dhcp-nameservers-client":
				addr = "dhcpNameserversClient"
			case "dynamic-gateways-client":
				addr = "gatewaysClient"
			case "static-system-nameservers-on-clash-start":
				currSystemNameservers, _, _ := netparam.GetSystemNameservers()
				if len(currSystemNameservers) == 0 {
					log.Warnln("%s: No current local DNS server was fetched.", u.Host)
				}
				nameservers, err = batchAddNameservers(nameservers, currSystemNameservers, u.Host)
				if err != nil {
					return nil, err
				}
				continue
			case "static-dhcp-nameservers-on-clash-start":
				currDhcpNameservers, _, _ := netparam.GetDhcpNameservers()
				if len(currDhcpNameservers) == 0 {
					log.Warnln("%s: No current DHCP DNS server was fetched.", u.Host)
				}
				nameservers, err = batchAddNameservers(nameservers, currDhcpNameservers, u.Host)
				if err != nil {
					return nil, err
				}
				continue
			case "static-gateways-on-clash-start":
				currGateways := netparam.GetGateways()
				if len(currGateways) == 0 {
					log.Warnln("%s: No current gateway was fetched.", u.Host)
				}
				nameservers, err = batchAddNameservers(nameservers, currGateways, u.Host)
				if err != nil {
					return nil, err
				}
				continue
			default:
				return nil, fmt.Errorf("DNS NameServer[%d] special:// bad body: %s", idx, u.Host)
			}
		case "quic":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "quic" // DNS over QUIC
		case "system":
			dnsNetType = "system" // System DNS
		case "rcode":
			dnsNetType = "rcode"
			addr = u.Host
			switch addr {
			case "success",
				"format_error",
				"server_failure",
				"name_error",
				"not_implemented",
				"refused":
			default:
				err = fmt.Errorf("unsupported RCode type: %s", addr)
			}
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		nameservers = append(
			nameservers,
			dns.NameServer{
				Net:       dnsNetType,
				Addr:      addr,
				ProxyName: proxyName,
				Params:    params,
				PreferH3:  preferH3,
			},
		)
	}
	return nameservers, nil
}

func init() {
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) { // using by wireguard
		return parseNameServer(servers, false)
	}
}

func parsePureDNSServer(server string) string {
	addPre := func(server string) string {
		return "udp://" + server
	}

	if server == "system" {
		return "system://"
	}

	if ip, err := netip.ParseAddr(server); err != nil {
		if strings.Contains(server, "://") {
			return server
		}
		return addPre(server)
	} else {
		if ip.Is4() {
			return addPre(server)
		} else {
			return addPre("[" + server + "]")
		}
	}
}
func parseNameServerPolicy(nsPolicy *orderedmap.OrderedMap[string, any], ruleProviders map[string]providerTypes.RuleProvider, preferH3 bool) (*orderedmap.OrderedMap[string, []dns.NameServer], error) {
	policy := orderedmap.New[string, []dns.NameServer]()
	updatedPolicy := orderedmap.New[string, any]()
	re := regexp.MustCompile(`[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?`)

	for pair := nsPolicy.Oldest(); pair != nil; pair = pair.Next() {
		k, v := pair.Key, pair.Value
		if strings.Contains(strings.ToLower(k), ",") {
			if strings.Contains(k, "geosite:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "geosite:" + subkey
					updatedPolicy.Store(newKey, v)
				}
			} else if strings.Contains(strings.ToLower(k), "rule-set:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "rule-set:" + subkey
					updatedPolicy.Store(newKey, v)
				}
			} else if re.MatchString(k) {
				subkeys := strings.Split(k, ",")
				for _, subkey := range subkeys {
					updatedPolicy.Store(subkey, v)
				}
			}
		} else {
			if strings.Contains(strings.ToLower(k), "geosite:") {
				updatedPolicy.Store("geosite:"+k[8:], v)
			} else if strings.Contains(strings.ToLower(k), "rule-set:") {
				updatedPolicy.Store("rule-set:"+k[9:], v)
			}
			updatedPolicy.Store(k, v)
		}
	}

	for pair := updatedPolicy.Oldest(); pair != nil; pair = pair.Next() {
		domain, server := pair.Key, pair.Value
		servers, err := utils.ToStringSlice(server)
		if err != nil {
			return nil, err
		}
		nameservers, err := parseNameServer(servers, preferH3)
		if err != nil {
			return nil, err
		}
		if _, valid := trie.ValidAndSplitDomain(domain); !valid {
			return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
		}
		if strings.HasPrefix(domain, "rule-set:") {
			domainSetName := domain[9:]
			if provider, ok := ruleProviders[domainSetName]; !ok {
				return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
			} else {
				switch provider.Behavior() {
				case providerTypes.IPCIDR:
					return nil, fmt.Errorf("rule provider type error, except domain,actual %s", provider.Behavior())
				case providerTypes.Classical:
					log.Warnln("%s provider is %s, only matching it contain domain rule", provider.Name(), provider.Behavior())
				}
			}
		}
		policy.Store(domain, nameservers)
	}

	return policy, nil
}

func parseFallbackIPCIDR(ips []string) ([]netip.Prefix, error) {
	var ipNets []netip.Prefix

	for idx, ip := range ips {
		ipnet, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %s", idx, err.Error())
		}
		ipNets = append(ipNets, ipnet)
	}

	return ipNets, nil
}

func parseFallbackGeoSite(countries []string, rules []C.Rule) ([]router.DomainMatcher, error) {
	var sites []router.DomainMatcher
	if len(countries) > 0 {
		if err := geodata.InitGeoSite(); err != nil {
			return nil, fmt.Errorf("can't initial GeoSite: %s", err)
		}
		log.Warnln("replace fallback-filter.geosite with nameserver-policy, it will be removed in the future")
	}

	for _, country := range countries {
		found := false
		for _, rule := range rules {
			if rule.RuleType() == C.GEOSITE {
				if strings.EqualFold(country, rule.Payload()) {
					found = true
					sites = append(sites, rule.(C.RuleGeoSite).GetDomainMatcher())
					log.Infoln("Start initial GeoSite dns fallback filter from rule `%s`", country)
				}
			}
		}

		if !found {
			matcher, recordsCount, err := geodata.LoadGeoSiteMatcher(country)
			if err != nil {
				return nil, err
			}

			sites = append(sites, matcher)

			log.Infoln("Start initial GeoSite dns fallback filter `%s`, records: %d", country, recordsCount)
		}
	}
	return sites, nil
}

func paresNTP(rawCfg *RawConfig) *NTP {
	cfg := rawCfg.NTP
	ntpCfg := &NTP{
		Enable:        cfg.Enable,
		Server:        cfg.Server,
		Port:          cfg.ServerPort,
		Interval:      cfg.Interval,
		DialerProxy:   cfg.DialerProxy,
		WriteToSystem: cfg.WriteToSystem,
	}
	return ntpCfg
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie[resolver.HostValue], rules []C.Rule, ruleProviders map[string]providerTypes.RuleProvider) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:       cfg.Enable,
		Listen:       cfg.Listen,
		PreferH3:     cfg.PreferH3,
		IPv6Timeout:  cfg.IPv6Timeout,
		IPv6:         cfg.IPv6,
		EnhancedMode: cfg.EnhancedMode,
		FallbackFilter: FallbackFilter{
			IPCIDR:  []netip.Prefix{},
			GeoSite: []router.DomainMatcher{},
		},
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy, ruleProviders, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.ProxyServerNameserver, err = parseNameServer(cfg.ProxyServerNameserver, cfg.PreferH3); err != nil {
		return nil, err
	}

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver, cfg.PreferH3); err != nil {
		return nil, err
	}
	// check default nameserver is pure ip addr
	for _, ns := range dnsCfg.DefaultNameserver {
		if ns.Net == "system" {
			continue
		}
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			u, err := url.Parse(ns.Addr)
			if err == nil && net.ParseIP(u.Host) == nil {
				if ip, _, err := net.SplitHostPort(u.Host); err != nil || net.ParseIP(ip) == nil {
					return nil, errors.New("default nameserver should be pure IP")
				}
			}
		}
	}

	fakeIPRange, err := netip.ParsePrefix(cfg.FakeIPRange)
	T.SetFakeIPRange(fakeIPRange)
	if cfg.EnhancedMode == C.DNSFakeIP {
		if err != nil {
			return nil, err
		}

		var host *trie.DomainTrie[struct{}]
		// fake ip skip host filter
		if len(cfg.FakeIPFilter) != 0 {
			host = trie.New[struct{}]()
			for _, domain := range cfg.FakeIPFilter {
				_ = host.Insert(domain, struct{}{})
			}
			host.Optimize()
		}

		if len(dnsCfg.Fallback) != 0 {
			if host == nil {
				host = trie.New[struct{}]()
			}
			for _, fb := range dnsCfg.Fallback {
				if net.ParseIP(fb.Addr) != nil {
					continue
				}
				_ = host.Insert(fb.Addr, struct{}{})
			}
			host.Optimize()
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       fakeIPRange,
			Size:        1000,
			Host:        host,
			Persistence: rawCfg.Profile.StoreFakeIP,
		})
		if err != nil {
			return nil, err
		}

		dnsCfg.FakeIPRange = pool
	}

	if len(cfg.Fallback) != 0 {
		dnsCfg.FallbackFilter.GeoIP = cfg.FallbackFilter.GeoIP
		dnsCfg.FallbackFilter.GeoIPCode = cfg.FallbackFilter.GeoIPCode
		if fallbackip, err := parseFallbackIPCIDR(cfg.FallbackFilter.IPCIDR); err == nil {
			dnsCfg.FallbackFilter.IPCIDR = fallbackip
		}
		dnsCfg.FallbackFilter.Domain = cfg.FallbackFilter.Domain
		fallbackGeoSite, err := parseFallbackGeoSite(cfg.FallbackFilter.GeoSite, rules)
		if err != nil {
			return nil, fmt.Errorf("load GeoSite dns fallback filter error, %w", err)
		}
		dnsCfg.FallbackFilter.GeoSite = fallbackGeoSite
	}

	if cfg.UseHosts {
		dnsCfg.Hosts = hosts
	}

	if cfg.CacheAlgorithm == "" || cfg.CacheAlgorithm == "lru" {
		dnsCfg.CacheAlgorithm = "lru"
	} else {
		dnsCfg.CacheAlgorithm = "arc"
	}

	return dnsCfg, nil
}

func parseAuthentication(rawRecords []string) []auth.AuthUser {
	var users []auth.AuthUser
	for _, line := range rawRecords {
		if user, pass, found := strings.Cut(line, ":"); found {
			users = append(users, auth.AuthUser{User: user, Pass: pass})
		}
	}
	return users
}

func parseTun(rawTun RawTun, general *General) error {
	tunAddressPrefix := T.FakeIPRange()
	if !tunAddressPrefix.IsValid() {
		tunAddressPrefix = netip.MustParsePrefix("198.18.0.1/16")
	}
	tunAddressPrefix = netip.PrefixFrom(tunAddressPrefix.Addr(), 30)

	if !general.IPv6 || !verifyIP6() {
		rawTun.Inet6Address = nil
	}

	general.Tun = LC.Tun{
		Enable:              rawTun.Enable,
		Device:              rawTun.Device,
		Stack:               rawTun.Stack,
		DNSHijack:           rawTun.DNSHijack,
		AutoRoute:           rawTun.AutoRoute,
		AutoDetectInterface: rawTun.AutoDetectInterface,
		RedirectToTun:       rawTun.RedirectToTun,

		MTU:                      rawTun.MTU,
		GSO:                      rawTun.GSO,
		GSOMaxSize:               rawTun.GSOMaxSize,
		Inet4Address:             []netip.Prefix{tunAddressPrefix},
		Inet6Address:             rawTun.Inet6Address,
		StrictRoute:              rawTun.StrictRoute,
		Inet4RouteAddress:        rawTun.Inet4RouteAddress,
		Inet6RouteAddress:        rawTun.Inet6RouteAddress,
		Inet4RouteExcludeAddress: rawTun.Inet4RouteExcludeAddress,
		Inet6RouteExcludeAddress: rawTun.Inet6RouteExcludeAddress,
		IncludeInterface:         rawTun.IncludeInterface,
		ExcludeInterface:         rawTun.ExcludeInterface,
		IncludeUID:               rawTun.IncludeUID,
		IncludeUIDRange:          rawTun.IncludeUIDRange,
		ExcludeUID:               rawTun.ExcludeUID,
		ExcludeUIDRange:          rawTun.ExcludeUIDRange,
		IncludeAndroidUser:       rawTun.IncludeAndroidUser,
		IncludePackage:           rawTun.IncludePackage,
		ExcludePackage:           rawTun.ExcludePackage,
		EndpointIndependentNat:   rawTun.EndpointIndependentNat,
		UDPTimeout:               rawTun.UDPTimeout,
		FileDescriptor:           rawTun.FileDescriptor,
	}

	return nil
}

func parseTuicServer(rawTuic RawTuicServer, general *General) error {
	general.TuicServer = LC.TuicServer{
		Enable:                rawTuic.Enable,
		Listen:                rawTuic.Listen,
		Token:                 rawTuic.Token,
		Users:                 rawTuic.Users,
		Certificate:           rawTuic.Certificate,
		PrivateKey:            rawTuic.PrivateKey,
		CongestionController:  rawTuic.CongestionController,
		MaxIdleTime:           rawTuic.MaxIdleTime,
		AuthenticationTimeout: rawTuic.AuthenticationTimeout,
		ALPN:                  rawTuic.ALPN,
		MaxUdpRelayPacketSize: rawTuic.MaxUdpRelayPacketSize,
		CWND:                  rawTuic.CWND,
	}
	return nil
}

func parseSniffer(snifferRaw RawSniffer) (*Sniffer, error) {
	sniffer := &Sniffer{
		Enable:          snifferRaw.Enable,
		ForceDnsMapping: snifferRaw.ForceDnsMapping,
		ParsePureIp:     snifferRaw.ParsePureIp,
	}
	loadSniffer := make(map[snifferTypes.Type]SNIFF.SnifferConfig)

	if len(snifferRaw.Sniff) != 0 {
		for sniffType, sniffConfig := range snifferRaw.Sniff {
			find := false
			ports, err := utils.NewUnsignedRangesFromList[uint16](sniffConfig.Ports)
			if err != nil {
				return nil, err
			}
			overrideDest := snifferRaw.OverrideDest
			if sniffConfig.OverrideDest != nil {
				overrideDest = *sniffConfig.OverrideDest
			}
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(sniffType) {
					find = true
					loadSniffer[snifferType] = SNIFF.SnifferConfig{
						Ports:        ports,
						OverrideDest: overrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", sniffType)
			}
		}
	} else {
		if sniffer.Enable {
			// Deprecated: Use Sniff instead
			log.Warnln("Deprecated: Use Sniff instead")
		}
		globalPorts, err := utils.NewUnsignedRangesFromList[uint16](snifferRaw.Ports)
		if err != nil {
			return nil, err
		}

		for _, snifferName := range snifferRaw.Sniffing {
			find := false
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(snifferName) {
					find = true
					loadSniffer[snifferType] = SNIFF.SnifferConfig{
						Ports:        globalPorts,
						OverrideDest: snifferRaw.OverrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", snifferName)
			}
		}
	}

	sniffer.Sniffers = loadSniffer

	forceDomainTrie := trie.New[struct{}]()
	for _, domain := range snifferRaw.ForceDomain {
		err := forceDomainTrie.Insert(domain, struct{}{})
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}
	sniffer.ForceDomain = forceDomainTrie.NewDomainSet()

	skipDomainTrie := trie.New[struct{}]()
	for _, domain := range snifferRaw.SkipDomain {
		err := skipDomainTrie.Insert(domain, struct{}{})
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}
	sniffer.SkipDomain = skipDomainTrie.NewDomainSet()

	return sniffer, nil
}
