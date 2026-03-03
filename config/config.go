package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "unsafe"

	"golang.org/x/exp/maps"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/orderedmap"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/dns/netparam"
	"github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	R "github.com/metacubex/mihomo/rules"
	RC "github.com/metacubex/mihomo/rules/common"
	RP "github.com/metacubex/mihomo/rules/provider"
	RW "github.com/metacubex/mihomo/rules/wrapper"
	T "github.com/metacubex/mihomo/tunnel"
	"github.com/samber/lo"

	"golang.org/x/exp/slices"
)

// General config
type General struct {
	Inbound
	Mode                    T.TunnelMode            `json:"mode"`
	UnifiedDelay            bool                    `json:"unified-delay"`
	LogLevel                log.LogLevel            `json:"log-level"`
	DelayTestUrl            string                  `json:"delay-test-url"`
	IPv6                    bool                    `json:"ipv6"`
	Interface               string                  `json:"interface-name"`
	RoutingMark             int                     `json:"routing-mark"`
	GeoXUrl                 GeoXUrl                 `json:"geox-url"`
	GeoAutoUpdate           bool                    `json:"geo-auto-update"`
	GeoUpdateInterval       int                     `json:"geo-update-interval"`
	GeodataMode             bool                    `json:"geodata-mode"`
	GeodataLoader           string                  `json:"geodata-loader"`
	GeositeMatcher          string                  `json:"geosite-matcher"`
	TCPConcurrent           bool                    `json:"tcp-concurrent"`
	FindProcessMode         process.FindProcessMode `json:"find-process-mode"`
	Sniffing                bool                    `json:"sniffing"`
	GlobalClientFingerprint string                  `json:"global-client-fingerprint"`
	GlobalUA                string                  `json:"global-ua"`
	ETagSupport             bool                    `json:"etag-support"`
	KeepAliveIdle           int                     `json:"keep-alive-idle"`
	KeepAliveInterval       int                     `json:"keep-alive-interval"`
	DisableKeepAlive        bool                    `json:"disable-keep-alive"`
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

// GeoXUrl config
type GeoXUrl struct {
	GeoIp   string `json:"geo-ip"`
	Mmdb    string `json:"mmdb"`
	ASN     string `json:"asn"`
	GeoSite string `json:"geo-site"`
}

// Controller config
type Controller struct {
	ExternalController     string
	ExternalControllerTLS  string
	ExternalControllerUnix string
	ExternalControllerPipe string
	ExternalUI             string
	ExternalUIURL          string
	ExternalUIName         string
	ExternalDohServer      string
	Secret                 string
	Cors                   Cors
}

type Cors struct {
	AllowOrigins        []string
	AllowPrivateNetwork bool
}

// Experimental config
type Experimental struct {
	QUICGoDisableGSO bool
	QUICGoDisableECN bool
	IP4PEnable       bool
}

// IPTables config
type IPTables struct {
	Enable           bool
	InboundInterface string
	Bypass           []string
	DnsRedirect      bool
}

// NTP config
type NTP struct {
	Enable        bool
	Server        string
	Port          int
	Interval      int
	DialerProxy   string
	WriteToSystem bool
}

// DNS config
type DNS struct {
	Enable                bool
	PreferH3              bool
	IPv6                  bool
	IPv6Timeout           uint
	UseHosts              bool
	UseSystemHosts        bool
	NameServer            []dns.NameServer
	Fallback              []dns.NameServer
	FallbackIPFilter      []C.IpMatcher
	FallbackDomainFilter  []C.DomainMatcher
	Listen                string
	EnhancedMode          C.DNSMode
	DefaultNameserver     []dns.NameServer
	CacheAlgorithm        string
	CacheMaxSize          int
	FakeIPRange           netip.Prefix
	FakeIPPool            *fakeip.Pool
	FakeIPRange6          netip.Prefix
	FakeIPPool6           *fakeip.Pool
	FakeIPSkipper         *fakeip.Skipper
	FakeIPTTL             int
	NameServerPolicy      []dns.Policy
	ProxyServerNameserver []dns.NameServer
	ProxyServerPolicy     []dns.Policy
	DirectNameServer      []dns.NameServer
	DirectFollowPolicy    bool
}

// Profile config
type Profile struct {
	StoreSelected bool
	StoreFakeIP   bool
}

// TLS config
type TLS struct {
	Certificate     string
	PrivateKey      string
	ClientAuthType  string
	ClientAuthCert  string
	EchKey          string
	CustomTrustCert []string
}

// Config is mihomo config manager
type Config struct {
	General                                 *General
	Controller                              *Controller
	Experimental                            *Experimental
	IPTables                                *IPTables
	NTP                                     *NTP
	DNS                                     *DNS
	Hosts                                   *trie.DomainTrie[resolver.HostValue]
	HostsDialIPDirectlyTrie                 *trie.DomainTrie[bool]
	Profile                                 *Profile
	Rules                                   []C.Rule
	SubRules                                map[string][]C.Rule
	Users                                   []auth.AuthUser
	Proxies                                 map[string]C.Proxy
	Listeners                               map[string]C.InboundListener
	Providers                               map[string]P.ProxyProvider
	RuleProviders                           map[string]P.RuleProvider
	Tunnels                                 []LC.Tunnel
	Reverses                                []T.ReverseConf
	ReverseSeeAsErrorIfDisconnectInMillisec int
	ReverseStopAfterErrorRetryCount         int
	ReverseEnableOnAndroidTypeTransports    []int
	ListenerFilterExcludePorts              []int
	T.Clashray
	Sniffer *sniffer.Config
	TLS     *TLS
}

type RawCors struct {
	AllowOrigins        []string `yaml:"allow-origins" json:"allow-origins"`
	AllowPrivateNetwork bool     `yaml:"allow-private-network" json:"allow-private-network"`
}

type RawDNS struct {
	Enable                       bool                                `yaml:"enable" json:"enable"`
	PreferH3                     bool                                `yaml:"prefer-h3" json:"prefer-h3"`
	IPv6                         bool                                `yaml:"ipv6" json:"ipv6"`
	IPv6Timeout                  uint                                `yaml:"ipv6-timeout" json:"ipv6-timeout"`
	UseHosts                     bool                                `yaml:"use-hosts" json:"use-hosts"`
	UseSystemHosts               bool                                `yaml:"use-system-hosts" json:"use-system-hosts"`
	RespectRules                 bool                                `yaml:"respect-rules" json:"respect-rules"`
	NameServer                   []string                            `yaml:"nameserver" json:"nameserver"`
	Fallback                     []string                            `yaml:"fallback" json:"fallback"`
	FallbackFilter               RawFallbackFilter                   `yaml:"fallback-filter" json:"fallback-filter"`
	Listen                       string                              `yaml:"listen" json:"listen"`
	EnhancedMode                 C.DNSMode                           `yaml:"enhanced-mode" json:"enhanced-mode"`
	FakeIPRange                  string                              `yaml:"fake-ip-range" json:"fake-ip-range"`
	FakeIPRange6                 string                              `yaml:"fake-ip-range6" json:"fake-ip-range6"`
	FakeIPFilter                 []string                            `yaml:"fake-ip-filter" json:"fake-ip-filter"`
	FakeIPFilterMode             C.FilterMode                        `yaml:"fake-ip-filter-mode" json:"fake-ip-filter-mode"`
	FakeIPTTL                    int                                 `yaml:"fake-ip-ttl" json:"fake-ip-ttl"`
	DefaultNameserver            []string                            `yaml:"default-nameserver" json:"default-nameserver"`
	CacheAlgorithm               string                              `yaml:"cache-algorithm" json:"cache-algorithm"`
	CacheMaxSize                 int                                 `yaml:"cache-max-size" json:"cache-max-size"`
	NameServerPolicy             *orderedmap.OrderedMap[string, any] `yaml:"nameserver-policy" json:"nameserver-policy"`
	ProxyServerNameserver        []string                            `yaml:"proxy-server-nameserver" json:"proxy-server-nameserver"`
	ProxyServerNameserverPolicy  *orderedmap.OrderedMap[string, any] `yaml:"proxy-server-nameserver-policy" json:"proxy-server-nameserver-policy"`
	DirectNameServer             []string                            `yaml:"direct-nameserver" json:"direct-nameserver"`
	DirectNameServerFollowPolicy bool                                `yaml:"direct-nameserver-follow-policy" json:"direct-nameserver-follow-policy"`
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

type RawNTP struct {
	Enable        bool   `yaml:"enable" json:"enable"`
	Server        string `yaml:"server" json:"server"`
	Port          int    `yaml:"port" json:"port"`
	Interval      int    `yaml:"interval" json:"interval"`
	DialerProxy   string `yaml:"dialer-proxy" json:"dialer-proxy"`
	WriteToSystem bool   `yaml:"write-to-system" json:"write-to-system"`
}

type RawTun struct {
	Enable              bool       `yaml:"enable" json:"enable"`
	Device              string     `yaml:"device" json:"device"`
	Stack               C.TUNStack `yaml:"stack" json:"stack"`
	DNSHijack           []string   `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool       `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool       `yaml:"auto-detect-interface"`

	MTU        uint32 `yaml:"mtu" json:"mtu,omitempty"`
	GSO        bool   `yaml:"gso" json:"gso,omitempty"`
	GSOMaxSize uint32 `yaml:"gso-max-size" json:"gso-max-size,omitempty"`
	//Inet4Address           []netip.Prefix `yaml:"inet4-address" json:"inet4-address,omitempty"`
	Inet6Address                          []netip.Prefix `yaml:"inet6-address" json:"inet6-address,omitempty"`
	IPRoute2TableIndex                    int            `yaml:"iproute2-table-index" json:"iproute2-table-index,omitempty"`
	IPRoute2RuleIndex                     int            `yaml:"iproute2-rule-index" json:"iproute2-rule-index,omitempty"`
	AutoRedirect                          bool           `yaml:"auto-redirect" json:"auto-redirect,omitempty"`
	AutoRedirectInputMark                 uint32         `yaml:"auto-redirect-input-mark" json:"auto-redirect-input-mark,omitempty"`
	AutoRedirectOutputMark                uint32         `yaml:"auto-redirect-output-mark" json:"auto-redirect-output-mark,omitempty"`
	AutoRedirectIPRoute2FallbackRuleIndex int            `yaml:"auto-redirect-iproute2-fallback-rule-index" json:"auto-redirect-iproute2-fallback-rule-index,omitempty"`
	LoopbackAddress                       []netip.Addr   `yaml:"loopback-address" json:"loopback-address,omitempty"`
	StrictRoute                           bool           `yaml:"strict-route" json:"strict-route,omitempty"`
	RouteAddress                          []netip.Prefix `yaml:"route-address" json:"route-address,omitempty"`
	RouteAddressSet                       []string       `yaml:"route-address-set" json:"route-address-set,omitempty"`
	RouteExcludeAddress                   []netip.Prefix `yaml:"route-exclude-address" json:"route-exclude-address,omitempty"`
	RouteExcludeAddressSet                []string       `yaml:"route-exclude-address-set" json:"route-exclude-address-set,omitempty"`
	IncludeInterface                      []string       `yaml:"include-interface" json:"include-interface,omitempty"`
	ExcludeInterface                      []string       `yaml:"exclude-interface" json:"exclude-interface,omitempty"`
	IncludeUID                            []uint32       `yaml:"include-uid" json:"include-uid,omitempty"`
	IncludeUIDRange                       []string       `yaml:"include-uid-range" json:"include-uid-range,omitempty"`
	ExcludeUID                            []uint32       `yaml:"exclude-uid" json:"exclude-uid,omitempty"`
	ExcludeUIDRange                       []string       `yaml:"exclude-uid-range" json:"exclude-uid-range,omitempty"`
	ExcludeSrcPort                        []uint16       `yaml:"exclude-src-port" json:"exclude-src-port,omitempty"`
	ExcludeSrcPortRange                   []string       `yaml:"exclude-src-port-range" json:"exclude-src-port-range,omitempty"`
	ExcludeDstPort                        []uint16       `yaml:"exclude-dst-port" json:"exclude-dst-port,omitempty"`
	ExcludeDstPortRange                   []string       `yaml:"exclude-dst-port-range" json:"exclude-dst-port-range,omitempty"`
	IncludeAndroidUser                    []int          `yaml:"include-android-user" json:"include-android-user,omitempty"`
	IncludePackage                        []string       `yaml:"include-package" json:"include-package,omitempty"`
	ExcludePackage                        []string       `yaml:"exclude-package" json:"exclude-package,omitempty"`
	EndpointIndependentNat                bool           `yaml:"endpoint-independent-nat" json:"endpoint-independent-nat,omitempty"`
	UDPTimeout                            int64          `yaml:"udp-timeout" json:"udp-timeout,omitempty"`
	DisableICMPForwarding                 bool           `yaml:"disable-icmp-forwarding" json:"disable-icmp-forwarding,omitempty"`
	FileDescriptor                        int            `yaml:"file-descriptor" json:"file-descriptor"`

	Inet4RouteAddress        []netip.Prefix `yaml:"inet4-route-address" json:"inet4-route-address,omitempty"`
	Inet6RouteAddress        []netip.Prefix `yaml:"inet6-route-address" json:"inet6-route-address,omitempty"`
	Inet4RouteExcludeAddress []netip.Prefix `yaml:"inet4-route-exclude-address" json:"inet4-route-exclude-address,omitempty"`
	Inet6RouteExcludeAddress []netip.Prefix `yaml:"inet6-route-exclude-address" json:"inet6-route-exclude-address,omitempty"`

	// darwin special config
	RecvMsgX bool `yaml:"recvmsgx" json:"recvmsgx,omitempty"`
	SendMsgX bool `yaml:"sendmsgx" json:"sendmsgx,omitempty"`
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

type RawIPTables struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	InboundInterface string   `yaml:"inbound-interface" json:"inbound-interface"`
	Bypass           []string `yaml:"bypass" json:"bypass"`
	DnsRedirect      bool     `yaml:"dns-redirect" json:"dns-redirect"`
}

type RawExperimental struct {
	Fingerprints     []string `yaml:"fingerprints"`
	QUICGoDisableGSO bool     `yaml:"quic-go-disable-gso"`
	QUICGoDisableECN bool     `yaml:"quic-go-disable-ecn"`
	IP4PEnable       bool     `yaml:"dialer-ip4p-convert"`
}

type RawProfile struct {
	StoreSelected bool `yaml:"store-selected" json:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip" json:"store-fake-ip"`
}

type RawGeoXUrl struct {
	GeoIp   string `yaml:"geoip" json:"geoip"`
	Mmdb    string `yaml:"mmdb" json:"mmdb"`
	ASN     string `yaml:"asn" json:"asn"`
	GeoSite string `yaml:"geosite" json:"geosite"`
}

type RawSniffer struct {
	Enable          bool     `yaml:"enable" json:"enable"`
	OverrideDest    bool     `yaml:"override-destination" json:"override-destination"`
	Sniffing        []string `yaml:"sniffing" json:"sniffing"`
	ForceDomain     []string `yaml:"force-domain" json:"force-domain"`
	SkipSrcAddress  []string `yaml:"skip-src-address" json:"skip-src-address"`
	SkipDstAddress  []string `yaml:"skip-dst-address" json:"skip-dst-address"`
	SkipDomain      []string `yaml:"skip-domain" json:"skip-domain"`
	Ports           []string `yaml:"port-whitelist" json:"port-whitelist"`
	ForceDnsMapping bool     `yaml:"force-dns-mapping" json:"force-dns-mapping"`
	ParsePureIp     bool     `yaml:"parse-pure-ip" json:"parse-pure-ip"`

	Sniff map[string]RawSniffingConfig `yaml:"sniff" json:"sniff"`
}

type RawSniffingConfig struct {
	Ports        []string `yaml:"ports" json:"ports"`
	OverrideDest *bool    `yaml:"override-destination" json:"override-destination"`
}

type RawTLS struct {
	Certificate     string   `yaml:"certificate" json:"certificate"`
	PrivateKey      string   `yaml:"private-key" json:"private-key"`
	ClientAuthType  string   `yaml:"client-auth-type" json:"client-auth-type"`
	ClientAuthCert  string   `yaml:"client-auth-cert" json:"client-auth-cert"`
	EchKey          string   `yaml:"ech-key" json:"ech-key"`
	CustomTrustCert []string `yaml:"custom-certifactes" json:"custom-certifactes"`
}

type RawConfig struct {
	Port                    int                     `yaml:"port" json:"port"`
	SocksPort               int                     `yaml:"socks-port" json:"socks-port"`
	RedirPort               int                     `yaml:"redir-port" json:"redir-port"`
	TProxyPort              int                     `yaml:"tproxy-port" json:"tproxy-port"`
	MixedPort               int                     `yaml:"mixed-port" json:"mixed-port"`
	ShadowSocksConfig       string                  `yaml:"ss-config" json:"ss-config"`
	VmessConfig             string                  `yaml:"vmess-config" json:"vmess-config"`
	InboundTfo              bool                    `yaml:"inbound-tfo" json:"inbound-tfo"`
	InboundMPTCP            bool                    `yaml:"inbound-mptcp" json:"inbound-mptcp"`
	Authentication          []string                `yaml:"authentication" json:"authentication"`
	SkipAuthPrefixes        []netip.Prefix          `yaml:"skip-auth-prefixes" json:"skip-auth-prefixes"`
	LanAllowedIPs           []netip.Prefix          `yaml:"lan-allowed-ips" json:"lan-allowed-ips"`
	LanDisAllowedIPs        []netip.Prefix          `yaml:"lan-disallowed-ips" json:"lan-disallowed-ips"`
	AllowLan                bool                    `yaml:"allow-lan" json:"allow-lan"`
	BindAddress             string                  `yaml:"bind-address" json:"bind-address"`
	Mode                    T.TunnelMode            `yaml:"mode" json:"mode"`
	UnifiedDelay            bool                    `yaml:"unified-delay" json:"unified-delay"`
	LogLevel                log.LogLevel            `yaml:"log-level" json:"log-level"`
	DelayTestUrl            string                  `yaml:"delay-test-url"`
	IPv6                    bool                    `yaml:"ipv6" json:"ipv6"`
	ExternalController      string                  `yaml:"external-controller" json:"external-controller"`
	ExternalControllerPipe  string                  `yaml:"external-controller-pipe" json:"external-controller-pipe"`
	ExternalControllerUnix  string                  `yaml:"external-controller-unix" json:"external-controller-unix"`
	ExternalControllerTLS   string                  `yaml:"external-controller-tls" json:"external-controller-tls"`
	ExternalControllerCors  RawCors                 `yaml:"external-controller-cors" json:"external-controller-cors"`
	ExternalUI              string                  `yaml:"external-ui" json:"external-ui"`
	ExternalUIURL           string                  `yaml:"external-ui-url" json:"external-ui-url"`
	ExternalUIName          string                  `yaml:"external-ui-name" json:"external-ui-name"`
	ExternalDohServer       string                  `yaml:"external-doh-server" json:"external-doh-server"`
	Secret                  string                  `yaml:"secret" json:"secret"`
	Interface               string                  `yaml:"interface-name" json:"interface-name"`
	RoutingMark             int                     `yaml:"routing-mark" json:"routing-mark"`
	Tunnels                 []LC.Tunnel             `yaml:"tunnels" json:"tunnels"`
	GeoAutoUpdate           bool                    `yaml:"geo-auto-update" json:"geo-auto-update"`
	GeoUpdateInterval       int                     `yaml:"geo-update-interval" json:"geo-update-interval"`
	GeodataMode             bool                    `yaml:"geodata-mode" json:"geodata-mode"`
	GeodataLoader           string                  `yaml:"geodata-loader" json:"geodata-loader"`
	GeositeMatcher          string                  `yaml:"geosite-matcher" json:"geosite-matcher"`
	TCPConcurrent           bool                    `yaml:"tcp-concurrent" json:"tcp-concurrent"`
	FindProcessMode         process.FindProcessMode `yaml:"find-process-mode" json:"find-process-mode"`
	GlobalClientFingerprint string                  `yaml:"global-client-fingerprint" json:"global-client-fingerprint"`
	GlobalUA                string                  `yaml:"global-ua" json:"global-ua"`
	ETagSupport             bool                    `yaml:"etag-support" json:"etag-support"`
	KeepAliveIdle           int                     `yaml:"keep-alive-idle" json:"keep-alive-idle"`
	KeepAliveInterval       int                     `yaml:"keep-alive-interval" json:"keep-alive-interval"`
	DisableKeepAlive        bool                    `yaml:"disable-keep-alive" json:"disable-keep-alive"`

	ProxyProvider map[string]map[string]any `yaml:"proxy-providers" json:"proxy-providers"`
	RuleProvider  map[string]map[string]any `yaml:"rule-providers" json:"rule-providers"`
	Proxy         []map[string]any          `yaml:"proxies" json:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups" json:"proxy-groups"`
	Rule          []string                  `yaml:"rules" json:"rule"`
	SubRules      map[string][]string       `yaml:"sub-rules" json:"sub-rules"`
	Listeners     []map[string]any          `yaml:"listeners" json:"listeners"`
	Reverses      []T.ReverseConf           `yaml:"reverses"`

	ReverseStopAfterErrorRetryCount         int   `yaml:"reverse-stop-after-error-retry-count"`
	ReverseSeeAsErrorIfDisconnectInMillisec int   `yaml:"reverse-see-as-error-if-disconnect-in-millisec"`
	ReverseEnableOnAndroidTypeTransports    []int `yaml:"reverse-enable-on-android-type-transports"`
	ListenerFilterExcludePorts              []int `yaml:"listener-filter-exclude-ports"`

	Hosts        map[string]any  `yaml:"hosts" json:"hosts"`
	DNS          RawDNS          `yaml:"dns" json:"dns"`
	NTP          RawNTP          `yaml:"ntp" json:"ntp"`
	Tun          RawTun          `yaml:"tun" json:"tun"`
	TuicServer   RawTuicServer   `yaml:"tuic-server" json:"tuic-server"`
	IPTables     RawIPTables     `yaml:"iptables" json:"iptables"`
	Experimental RawExperimental `yaml:"experimental" json:"experimental"`
	Profile      RawProfile      `yaml:"profile" json:"profile"`
	GeoXUrl      RawGeoXUrl      `yaml:"geox-url" json:"geox-url"`
	Sniffer      RawSniffer      `yaml:"sniffer" json:"sniffer"`
	TLS          RawTLS          `yaml:"tls" json:"tls"`

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
	ClashrayTestCORSAllowedOrigins              []string                   `yaml:"clashray-test-cors-allowed-origins"`
	ClashrayCurrPublisherAppendServices         []string                   `yaml:"clashray-curr-publisher-append-services"`
	ClashrayCurrPublisherAppendLanContacts      []map[string]interface{}   `yaml:"clashray-curr-publisher-append-lan-contacts"`
	ClashrayCurrPublisherAppendReverseContacts  []T.ClashrayReverseContact `yaml:"clashray-curr-publisher-append-reverse-contacts"`
}

// Parse config
func Parse(buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}

	return ParseRawConfig(rawCfg)
}

func DefaultRawConfig() *RawConfig {
	return &RawConfig{
		AllowLan:          false,
		BindAddress:       "*",
		LanAllowedIPs:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		IPv6:              true,
		Mode:              T.Rule,
		GeoAutoUpdate:     false,
		GeoUpdateInterval: 24,
		GeodataMode:       geodata.GeodataMode(),
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
		FindProcessMode:   process.FindProcessStrict,
		GlobalUA:          "clash.meta/" + C.Version,
		ETagSupport:       true,
		DNS: RawDNS{
			Enable:         false,
			IPv6:           false,
			UseHosts:       true,
			UseSystemHosts: true,
			IPv6Timeout:    100,
			EnhancedMode:   C.DNSMapping,
			FakeIPRange:    "198.18.0.1/16",
			FakeIPTTL:      1,
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
			FakeIPFilterMode: C.FilterBlackList,
		},
		NTP: RawNTP{
			Enable:        false,
			WriteToSystem: false,
			Server:        "time.apple.com",
			Port:          123,
			Interval:      30,
		},
		Tun: RawTun{
			Enable:              false,
			Device:              "",
			Stack:               C.TunGvisor,
			DNSHijack:           []string{"0.0.0.0:53"}, // default hijack all dns query
			AutoRoute:           true,
			AutoDetectInterface: true,
			Inet6Address:        []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
			RecvMsgX:            true,
			SendMsgX:            false, // In the current implementation, if enabled, the kernel may freeze during multi-thread downloads, so it is disabled by default.
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
		IPTables: RawIPTables{
			Enable:           false,
			InboundInterface: "lo",
			Bypass:           []string{},
			DnsRedirect:      true,
		},
		Experimental: RawExperimental{
			// https://github.com/quic-go/quic-go/issues/4178
			// Quic-go currently cannot automatically fall back on platforms that do not support ecn, so this feature is turned off by default.
			QUICGoDisableECN: true,
		},
		Profile: RawProfile{
			StoreSelected: true,
		},
		GeoXUrl: RawGeoXUrl{
			Mmdb:    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
			ASN:     "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
			GeoIp:   "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
			GeoSite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
		},
		Sniffer: RawSniffer{
			Enable:          false,
			Sniff:           map[string]RawSniffingConfig{},
			ForceDomain:     []string{},
			SkipDomain:      []string{},
			Ports:           []string{},
			ForceDnsMapping: true,
			ParsePureIp:     true,
			OverrideDest:    true,
		},
		ExternalUIURL: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",

		ClashrayNetCurrAsPublisher: "",
		ClashrayNetCurrIsAsVisitor: false,
		// ClashrayNetVisitorTunnelNoHostsNorListening: false,
		ClashrayNetVisitorTunnelNoHostsNorListening: true,
		ExternalControllerCors: RawCors{
			AllowOrigins:        []string{"*"},
			AllowPrivateNetwork: true,
		},
	}
}

func UnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	// config with default value
	rawCfg := DefaultRawConfig()

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
	config.Clashray.ClashrayTestCORSAllowedOrigins = rawCfg.ClashrayTestCORSAllowedOrigins
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
	if config.Clashray.ClashrayTestCORSAllowedOrigins == nil {
		config.Clashray.ClashrayTestCORSAllowedOrigins = make([]string, 0)
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
							visitorNotPublisherHTTPRedirectMap[httpRedirectHost] = "auto-added:" + httpRedirectTarget
							visitorNotPublisherPayloadConnHTTPRedirectRules = append(visitorNotPublisherPayloadConnHTTPRedirectRules, fmt.Sprintf("%s,%s,%s", "DOMAIN", httpRedirectHost, "INTERNAL-HTTP:::CLASHRAY-HTTP-REDIRECT"))
						}

						publisherAlsoVisitorHTTPRedirectMap[httpRedirectHost] = "auto-added:" + httpRedirectTarget
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
			rawCfg.ClashrayTestCORSAllowedOrigins = append(rawCfg.ClashrayTestCORSAllowedOrigins, publisherCORSAllowed...)
			config.Clashray.ClashrayTestCORSAllowedOrigins = append(config.Clashray.ClashrayTestCORSAllowedOrigins, publisherCORSAllowed...)
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
				if rawCfg.DNS.EnhancedMode == C.DNSFakeIP {
					// shunf4 mod: on my android devices, we can't have any hosts for local listeners. these hosts should be resolved to fake ips, and proxied, allowing connections to any ports, including priveleged 80, to be processed..
				} else {
					maps.Copy(rawCfg.Hosts, visitorNotPublisherHosts)
				}
			}

			rawCfg.ClashrayTestCORSAllowedOrigins = append(rawCfg.ClashrayTestCORSAllowedOrigins, visitorNotPublisherCORSAllowed...)
			config.Clashray.ClashrayTestCORSAllowedOrigins = append(config.Clashray.ClashrayTestCORSAllowedOrigins, visitorNotPublisherCORSAllowed...)
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
				if rawCfg.DNS.EnhancedMode == C.DNSFakeIP {
					// shunf4 mod: on my android devices, we can't have any hosts for local listeners. these hosts should be resolved to fake ips, and proxied, allowing connections to any ports, including priveleged 80, to be processed..
				} else {
					maps.Copy(rawCfg.Hosts, publisherAlsoVisitorHosts)
				}
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

			for httpRedirectHost, v := range config.Clashray.ClashrayHTTPRedirectMap {
				if strings.HasPrefix(v, "no-hosts:") || strings.HasPrefix(v, "no-hosts-nor-rule:") {
					continue
				}
				if rawCfg.DNS.EnhancedMode == C.DNSFakeIP {
					// shunf4 mod: on my android devices, we can't have any hosts for local listeners. these hosts should be resolved to fake ips, and proxied, allowing connections to any ports, including priveleged 80, to be processed..
				} else {
					rawCfg.Hosts[httpRedirectHost] = httpRedirectListener["listen"]
				}
			}
		}
	}
	rawCfg.SubRules["clashray-http-redirect-rule"] = []string{
		"MATCH,INTERNAL-HTTP:::CLASHRAY-HTTP-REDIRECT",
	}

	manuallyAddedHTTPRedirectRules := []string{}
	for httpRedirectHost, v := range config.Clashray.ClashrayHTTPRedirectMap {
		if strings.HasPrefix(v, "no-rule:") || strings.HasPrefix(v, "no-hosts-nor-rule:") || strings.HasPrefix(v, "auto-added:") {
			continue
		}
		manuallyAddedHTTPRedirectRules = append(manuallyAddedHTTPRedirectRules, fmt.Sprintf("%s,%s,%s", "DOMAIN", httpRedirectHost, "INTERNAL-HTTP:::CLASHRAY-HTTP-REDIRECT"))
	}
	if len(manuallyAddedHTTPRedirectRules) > 0 {
		rawCfg.Rule = append(manuallyAddedHTTPRedirectRules, rawCfg.Rule...)
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

			if rawCfg.DNS.EnhancedMode == C.DNSFakeIP {
				// shunf4 mod: on my android devices, we can't have any hosts for local listeners. these hosts should be resolved to fake ips, and proxied, allowing connections to any ports, including priveleged 80, to be processed..
			} else {
				rawCfg.Hosts["test.clashray.home.arpa"] = clashrayTestListener["listen"]
			}
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

			if rawCfg.DNS.EnhancedMode == C.DNSFakeIP {
				// shunf4 mod: on my android devices, we can't have any hosts for local listeners. these hosts should be resolved to fake ips, and proxied, allowing connections to any ports, including priveleged 80, to be processed..
			} else {
				rawCfg.Hosts["send.clashray.home.arpa"] = clashraySendListener["listen"]
			}
		}
	}
	rawCfg.SubRules["clashray-send-rule"] = []string{
		"MATCH,INTERNAL-HTTP:::CLASHRAY-SEND",
	}

	rawCfg.Rule = append([]string{"DOMAIN-SUFFIX,test.clashray.home.arpa,INTERNAL-HTTP:::CLASHRAY-TEST", "DOMAIN-SUFFIX,send.clashray.home.arpa,INTERNAL-HTTP:::CLASHRAY-SEND"}, rawCfg.Rule...)
	rawCfg.ClashrayTestCORSAllowedOrigins = append(rawCfg.ClashrayTestCORSAllowedOrigins, "test.clashray.home.arpa")
	config.Clashray.ClashrayTestCORSAllowedOrigins = append(config.Clashray.ClashrayTestCORSAllowedOrigins, "test.clashray.home.arpa")
	rawCfg.ClashrayTestCORSAllowedOrigins = append(rawCfg.ClashrayTestCORSAllowedOrigins, "send.clashray.home.arpa")
	config.Clashray.ClashrayTestCORSAllowedOrigins = append(config.Clashray.ClashrayTestCORSAllowedOrigins, "send.clashray.home.arpa")

	////// shunf4 mod: clashray-net: end

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	// We need to temporarily apply some configuration in general and roll back after parsing the complete configuration.
	// The loading and downloading of geodata in the parseRules and parseRuleProviders rely on these.
	// This implementation is very disgusting, but there is currently no better solution
	rollback := temporaryUpdateGeneral(config.General)
	defer rollback()

	controller, err := parseController(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Controller = controller

	experimental, err := parseExperimental(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Experimental = experimental

	iptables, err := parseIPTables(rawCfg)
	if err != nil {
		return nil, err
	}
	config.IPTables = iptables

	ntpCfg, err := parseNTP(rawCfg)
	if err != nil {
		return nil, err
	}
	config.NTP = ntpCfg

	profile, err := parseProfile(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Profile = profile

	tlsCfg, err := parseTLS(rawCfg)
	if err != nil {
		return nil, err
	}
	config.TLS = tlsCfg

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	config.ListenerFilterExcludePorts = rawCfg.ListenerFilterExcludePorts
	if config.ListenerFilterExcludePorts == nil {
		config.ListenerFilterExcludePorts = []int{}
	}
	listeners, err := parseListeners(rawCfg, config.ListenerFilterExcludePorts)
	if err != nil {
		return nil, err
	}
	config.Listeners = listeners

	log.Infoln("Geodata Loader mode: %s", geodata.LoaderName())
	log.Infoln("Geosite Matcher implementation: %s", geodata.SiteMatcherName())
	ruleProviders, err := parseRuleProviders(rawCfg)
	if err != nil {
		return nil, err
	}
	config.RuleProviders = ruleProviders

	subRules, err := parseSubRules(rawCfg, proxies, ruleProviders)
	if err != nil {
		return nil, err
	}
	config.SubRules = subRules

	rules, err := parseRules(rawCfg.Rule, proxies, ruleProviders, subRules, "rules")
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

	parseIPV6(rawCfg) // must before DNS and Tun

	dnsCfg, err := parseDNS(rawCfg, ruleProviders)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	err = parseTun(rawCfg.Tun, dnsCfg, config.General)
	if err != nil {
		return nil, err
	}

	err = parseTuicServer(rawCfg.TuicServer, config.General)
	if err != nil {
		return nil, err
	}

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Tunnels = make([]LC.Tunnel, 0)
	for i := range rawCfg.Tunnels {
		t := &rawCfg.Tunnels[i]
		_, tPortStr, err := net.SplitHostPort(t.Address)
		if err != nil {
			log.Warnln("filtering config.Tunnels by ListenerFilterExcludePorts: can't do SplitHostPort to this addr: %s", t.Address)
			// Go on
		} else {
			tPortRaw, err := strconv.ParseUint(tPortStr, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("filtering config.Tunnels by ListenerFilterExcludePorts: bad port: %s in addr: %s", tPortStr, t.Address)
			}
			tPort := int(tPortRaw)
			if lo.Contains(config.ListenerFilterExcludePorts, tPort) {
				log.Infoln("filtering config.Tunnels by ListenerFilterExcludePorts: filtered out this tunnel: %#v", t)
				// Exclude this tunnel
				continue
			}
		}
		config.Tunnels = append(config.Tunnels, *t)
	}
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

	config.Sniffer, err = parseSniffer(rawCfg.Sniffer, ruleProviders)
	if err != nil {
		return nil, err
	}

	elapsedTime := time.Since(startTime) / time.Millisecond                     // duration in ms
	log.Infoln("Initial configuration complete, total time: %dms", elapsedTime) //Segment finished in xxm

	T.SaveClashCurrRawConfig(yaml.Marshal(rawCfg))

	return config, nil
}

//go:linkname temporaryUpdateGeneral
func temporaryUpdateGeneral(general *General) func()

func parseGeneral(cfg *RawConfig) (*General, error) {
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
		UnifiedDelay: cfg.UnifiedDelay,
		Mode:         cfg.Mode,
		LogLevel:     cfg.LogLevel,
		DelayTestUrl: cfg.DelayTestUrl,
		IPv6:         cfg.IPv6,
		Interface:    cfg.Interface,
		RoutingMark:  cfg.RoutingMark,
		GeoXUrl: GeoXUrl{
			GeoIp:   cfg.GeoXUrl.GeoIp,
			Mmdb:    cfg.GeoXUrl.Mmdb,
			ASN:     cfg.GeoXUrl.ASN,
			GeoSite: cfg.GeoXUrl.GeoSite,
		},
		GeoAutoUpdate:           cfg.GeoAutoUpdate,
		GeoUpdateInterval:       cfg.GeoUpdateInterval,
		GeodataMode:             cfg.GeodataMode,
		GeodataLoader:           cfg.GeodataLoader,
		GeositeMatcher:          cfg.GeositeMatcher,
		TCPConcurrent:           cfg.TCPConcurrent,
		FindProcessMode:         cfg.FindProcessMode,
		GlobalClientFingerprint: cfg.GlobalClientFingerprint,
		GlobalUA:                cfg.GlobalUA,
		ETagSupport:             cfg.ETagSupport,
		KeepAliveIdle:           cfg.KeepAliveIdle,
		KeepAliveInterval:       cfg.KeepAliveInterval,
		DisableKeepAlive:        cfg.DisableKeepAlive,
	}, nil
}

func parseController(cfg *RawConfig) (*Controller, error) {
	if path := cfg.ExternalUI; path != "" && !C.Path.IsSafePath(path) {
		return nil, C.Path.ErrNotSafePath(path)
	}
	if uiName := cfg.ExternalUIName; uiName != "" && !filepath.IsLocal(uiName) {
		return nil, fmt.Errorf("external UI name is not local: %s", uiName)
	}
	return &Controller{
		ExternalController:     cfg.ExternalController,
		ExternalUI:             cfg.ExternalUI,
		ExternalUIURL:          cfg.ExternalUIURL,
		ExternalUIName:         cfg.ExternalUIName,
		Secret:                 cfg.Secret,
		ExternalControllerPipe: cfg.ExternalControllerPipe,
		ExternalControllerUnix: cfg.ExternalControllerUnix,
		ExternalControllerTLS:  cfg.ExternalControllerTLS,
		ExternalDohServer:      cfg.ExternalDohServer,
		Cors: Cors{
			AllowOrigins:        cfg.ExternalControllerCors.AllowOrigins,
			AllowPrivateNetwork: cfg.ExternalControllerCors.AllowPrivateNetwork,
		},
	}, nil
}

func parseExperimental(cfg *RawConfig) (*Experimental, error) {
	return &Experimental{
		QUICGoDisableGSO: cfg.Experimental.QUICGoDisableGSO,
		QUICGoDisableECN: cfg.Experimental.QUICGoDisableECN,
		IP4PEnable:       cfg.Experimental.IP4PEnable,
	}, nil
}

func parseIPTables(cfg *RawConfig) (*IPTables, error) {
	return &IPTables{
		Enable:           cfg.IPTables.Enable,
		InboundInterface: cfg.IPTables.InboundInterface,
		Bypass:           cfg.IPTables.Bypass,
		DnsRedirect:      cfg.IPTables.DnsRedirect,
	}, nil
}

func parseNTP(cfg *RawConfig) (*NTP, error) {
	return &NTP{
		Enable:        cfg.NTP.Enable,
		Server:        cfg.NTP.Server,
		Port:          cfg.NTP.Port,
		Interval:      cfg.NTP.Interval,
		DialerProxy:   cfg.NTP.DialerProxy,
		WriteToSystem: cfg.NTP.WriteToSystem,
	}, nil
}

func parseProfile(cfg *RawConfig) (*Profile, error) {
	return &Profile{
		StoreSelected: cfg.Profile.StoreSelected,
		StoreFakeIP:   cfg.Profile.StoreFakeIP,
	}, nil
}

func parseTLS(cfg *RawConfig) (*TLS, error) {
	return &TLS{
		Certificate:     cfg.TLS.Certificate,
		PrivateKey:      cfg.TLS.PrivateKey,
		ClientAuthType:  cfg.TLS.ClientAuthType,
		ClientAuthCert:  cfg.TLS.ClientAuthCert,
		EchKey:          cfg.TLS.EchKey,
		CustomTrustCert: cfg.TLS.CustomTrustCert,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]P.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]P.ProxyProvider)
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider

	var (
		proxyList  []string
		AllProxies []string
		hasGlobal  bool
	)

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
	}

	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		if groupName == "GLOBAL" {
			hasGlobal = true
		}
		proxyList = append(proxyList, groupName)
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

	slices.Sort(AllProxies)
	slices.Sort(AllProviders)

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

	if !hasGlobal {
		global := outboundgroup.NewSelector(
			&outboundgroup.GroupCommonOption{
				Name: "GLOBAL",
			},
			[]P.ProxyProvider{pd},
		)
		proxies["GLOBAL"] = adapter.NewProxy(global)
	}

	// validate dialer-proxy references
	if err := validateDialerProxies(proxies); err != nil {
		return nil, nil, err
	}

	return proxies, providersMap, nil
}

func parseListeners(cfg *RawConfig, filterExcludePorts []int) (listeners map[string]C.InboundListener, err error) {
	listener.ParseListenersStart()
	defer listener.ParseListenersEnd()
	listeners = make(map[string]C.InboundListener)
	for index, mapping := range cfg.Listeners {

		lPortAny, hasPort := mapping["port"]
		if !hasPort {
			log.Warnln("filtering config.Listeners by ListenerFilterExcludePorts: missing port in this listener: %#v", mapping)
		}
		lPortStr := fmt.Sprintf("%d", lPortAny)
		lPortRaw, err := strconv.ParseUint(lPortStr, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("filtering config.Listeners by ListenerFilterExcludePorts: bad port: %s in listener: %#v", lPortStr, mapping)
		}
		lPort := int(lPortRaw)
		if lo.Contains(filterExcludePorts, lPort) {
			log.Infoln("filtering config.Listeners by ListenerFilterExcludePorts: filtered out this listener: %#v", mapping)
			// Exclude this listener
			continue
		}

		inboundListener, err := listener.ParseListener(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", index, err)
		}

		name := inboundListener.Name()
		if _, exist := mapping[name]; exist {
			return nil, fmt.Errorf("listener %s is the duplicate name", name)
		}

		listeners[name] = inboundListener

	}
	return
}

func parseRuleProviders(cfg *RawConfig) (ruleProviders map[string]P.RuleProvider, err error) {
	RP.SetTunnel(T.Tunnel)
	ruleProviders = map[string]P.RuleProvider{}
	// parse rule provider
	for name, mapping := range cfg.RuleProvider {
		rp, err := RP.ParseRuleProvider(name, mapping, R.ParseRule)
		if err != nil {
			return nil, err
		}

		ruleProviders[name] = rp
	}
	return
}

func parseSubRules(cfg *RawConfig, proxies map[string]C.Proxy, ruleProviders map[string]P.RuleProvider) (subRules map[string][]C.Rule, err error) {
	subRules = map[string][]C.Rule{}
	for name := range cfg.SubRules {
		subRules[name] = make([]C.Rule, 0)
	}
	for name, rawRules := range cfg.SubRules {
		if len(name) == 0 {
			return nil, fmt.Errorf("sub-rule name is empty")
		}
		var rules []C.Rule
		rules, err = parseRules(rawRules, proxies, ruleProviders, subRules, fmt.Sprintf("sub-rules[%s]", name))
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

func parseRules(rulesConfig []string, proxies map[string]C.Proxy, ruleProviders map[string]P.RuleProvider, subRules map[string][]C.Rule, format string) ([]C.Rule, error) {
	var rules []C.Rule

	// parse rules
	for idx, line := range rulesConfig {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		if target == "" {
			return nil, fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
		}

		targetParts := strings.Split(target, ":::")
		if _, ok := proxies[targetParts[0]]; !ok {
			if tp != "SUB-RULE" {
				return nil, fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
			} else if _, ok = subRules[target]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
			}
		}

		parsed, parseErr := R.ParseRule(tp, payload, target, params, subRules)
		if parseErr != nil {
			return nil, fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, parseErr.Error())
		}

		for _, name := range parsed.ProviderNames() {
			if _, ok := ruleProviders[name]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: rule set [%s] not found", format, idx, line, name)
			}
		}

		if format == "rules" { // only wrap top level rules
			parsed = RW.NewRuleWrapper(parsed)
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
			hosts, err := utils.ToStringSlice(anyValue)
			if err != nil {
				return nil, nil, err
			}
			if len(hosts) == 1 && hosts[0] == "lan" {
				if addrs, err := net.InterfaceAddrs(); err != nil {
					log.Errorln("insert lan to host error: %s", err)
				} else {
					hosts = make([]string, 0, len(addrs))
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
							hosts = append(hosts, ipnet.IP.String())
						}
					}
				}
			}
			hasDialIPDirectlySuffix := false
			domain, hasDialIPDirectlySuffix = strings.CutSuffix(domain, ",dial-ip-directly")
			if str, ok := anyValue.(string); ok {
				anyValue, hasDialIPDirectlySuffix = strings.CutSuffix(str, ",dial-ip-directly")
			}

			value, err := resolver.NewHostValue(hosts)
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

func parseNameServer(servers []string, respectRules bool, preferH3 bool) ([]dns.NameServer, error) {
	var nameservers []dns.NameServer

	for idx, server := range servers {
		server = parsePureDNSServer(server)
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		var proxyName string
		params := map[string]string{}
		for _, s := range strings.Split(u.Fragment, "&") {
			arr := strings.SplitN(s, "=", 2)
			switch len(arr) {
			case 1:
				proxyName = arr[0]
			case 2:
				params[arr[0]] = arr[1]
			}
		}

		var addr, dnsNetType string
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "" // UDP
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp" // TCP
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tls" // DNS over TLS
		case "http", "https":
			addr, err = hostWithDefaultPort(u.Host, "443")
			dnsNetType = "https" // DNS over HTTPS
			if u.Scheme == "http" {
				addr, err = hostWithDefaultPort(u.Host, "80")
			}
			if err == nil {
				clearURL := url.URL{Scheme: u.Scheme, Host: addr, Path: u.Path, User: u.User}
				addr = clearURL.String()
			}
		case "special":
			dnsNetType = "special"
			specialParts := strings.Split(u.Host, ":")
			overridePortColon := ""
			if len(specialParts) > 1 {
				overridePortColon = ":" + specialParts[len(specialParts)-1]
				u.Host = strings.Join(specialParts[0:len(specialParts)-1], ":")
			}
			switch u.Host {
			case "dynamic-system-resolve-client":
				addr = "localResolveClient" + overridePortColon
			case "dynamic-dhcp-nameservers-client":
				addr = "dhcpNameserversClient" + overridePortColon
			case "dynamic-gateways-client":
				addr = "gatewaysClient" + overridePortColon
			case "static-system-nameservers-on-clash-start":
				currSystemNameservers, _, _ := netparam.GetSystemNameservers()
				if len(currSystemNameservers) == 0 {
					log.Warnln("%s: No current local DNS server was fetched.", u.Host)
				}
				currSystemNameservers = lo.Map(currSystemNameservers, func(x string, i int) string { return x + overridePortColon })
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
				currDhcpNameservers = lo.Map(currDhcpNameservers, func(x string, i int) string { return x + overridePortColon })
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
				currGateways = lo.Map(currGateways, func(x string, i int) string { return x + overridePortColon })
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
		case "dhcp":
			addr = server[len("dhcp://"):] // some special notation cannot be parsed by url
			dnsNetType = "dhcp"            // UDP from DHCP
			if addr == "system" {          // Compatible with old writing "dhcp://system"
				dnsNetType = "system"
				addr = ""
			}
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

		if respectRules && len(proxyName) == 0 {
			proxyName = dns.RespectRules
		}

		nameserver := dns.NameServer{
			Net:       dnsNetType,
			Addr:      addr,
			ProxyName: proxyName,
			Params:    params,
			PreferH3:  preferH3,
		}
		if slices.ContainsFunc(nameservers, nameserver.Equal) {
			continue // skip duplicates nameserver
		}

		nameservers = append(nameservers, nameserver)
	}
	return nameservers, nil
}

func init() {
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) { // using by wireguard
		return parseNameServer(servers, false, false)
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

func parseNameServerPolicy(nsPolicy *orderedmap.OrderedMap[string, any], ruleProviders map[string]P.RuleProvider, respectRules bool, preferH3 bool) ([]dns.Policy, error) {
	var policy []dns.Policy

	for pair := nsPolicy.Oldest(); pair != nil; pair = pair.Next() {
		k, v := pair.Key, pair.Value
		servers, err := utils.ToStringSlice(v)
		if err != nil {
			return nil, err
		}
		nameservers, err := parseNameServer(servers, respectRules, preferH3)
		if err != nil {
			return nil, err
		}
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, ",") {
			if strings.HasPrefix(kLower, "geosite:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "geosite:" + subkey
					policy = append(policy, dns.Policy{Domain: newKey, NameServers: nameservers})
				}
			} else if strings.HasPrefix(kLower, "rule-set:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "rule-set:" + subkey
					policy = append(policy, dns.Policy{Domain: newKey, NameServers: nameservers})
				}
			} else {
				subkeys := strings.Split(k, ",")
				for _, subkey := range subkeys {
					policy = append(policy, dns.Policy{Domain: subkey, NameServers: nameservers})
				}
			}
		} else {
			if strings.HasPrefix(kLower, "geosite:") {
				policy = append(policy, dns.Policy{Domain: "geosite:" + k[8:], NameServers: nameservers})
			} else if strings.HasPrefix(kLower, "rule-set:") {
				policy = append(policy, dns.Policy{Domain: "rule-set:" + k[9:], NameServers: nameservers})
			} else {
				policy = append(policy, dns.Policy{Domain: k, NameServers: nameservers})
			}
		}
	}

	for idx, p := range policy {
		domain, nameservers := p.Domain, p.NameServers

		if strings.HasPrefix(domain, "rule-set:") {
			domainSetName := domain[9:]
			matcher, err := parseDomainRuleSet(domainSetName, "dns.nameserver-policy", ruleProviders)
			if err != nil {
				return nil, err
			}
			policy[idx] = dns.Policy{Matcher: matcher, NameServers: nameservers}
		} else if strings.HasPrefix(domain, "geosite:") {
			country := domain[8:]
			matcher, err := RC.NewGEOSITE(country, "dns.nameserver-policy")
			if err != nil {
				return nil, err
			}
			policy[idx] = dns.Policy{Matcher: matcher, NameServers: nameservers}
		} else {
			if _, valid := trie.ValidAndSplitDomain(domain); !valid {
				return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
			}
		}
	}

	return policy, nil
}

func parseDNS(rawCfg *RawConfig, ruleProviders map[string]P.RuleProvider) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	if cfg.RespectRules && len(cfg.ProxyServerNameserver) == 0 {
		return nil, fmt.Errorf("if “respect-rules” is turned on, “proxy-server-nameserver” cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:         cfg.Enable,
		Listen:         cfg.Listen,
		PreferH3:       cfg.PreferH3,
		IPv6Timeout:    cfg.IPv6Timeout,
		IPv6:           cfg.IPv6,
		UseHosts:       cfg.UseHosts,
		UseSystemHosts: cfg.UseSystemHosts,
		EnhancedMode:   cfg.EnhancedMode,
		CacheAlgorithm: cfg.CacheAlgorithm,
		CacheMaxSize:   cfg.CacheMaxSize,
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer, cfg.RespectRules, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback, cfg.RespectRules, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy, ruleProviders, cfg.RespectRules, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.ProxyServerNameserver, err = parseNameServer(cfg.ProxyServerNameserver, false, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.ProxyServerPolicy, err = parseNameServerPolicy(cfg.ProxyServerNameserverPolicy, ruleProviders, false, cfg.PreferH3); err != nil {
		return nil, err
	}
	if len(dnsCfg.ProxyServerPolicy) != 0 && len(dnsCfg.ProxyServerNameserver) == 0 {
		return nil, errors.New("disallow empty `proxy-server-nameserver` when `proxy-server-nameserver-policy` is set")
	}

	if dnsCfg.DirectNameServer, err = parseNameServer(cfg.DirectNameServer, false, cfg.PreferH3); err != nil {
		return nil, err
	}
	dnsCfg.DirectFollowPolicy = cfg.DirectNameServerFollowPolicy

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver, false, cfg.PreferH3); err != nil {
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

	if cfg.FakeIPRange != "" {
		dnsCfg.FakeIPRange, err = netip.ParsePrefix(cfg.FakeIPRange)
		if err != nil {
			return nil, err
		}
		if !dnsCfg.FakeIPRange.Addr().Is4() {
			return nil, errors.New("dns.fake-ip-range must be a IPv4 prefix")
		}
	}

	if cfg.FakeIPRange6 != "" {
		dnsCfg.FakeIPRange6, err = netip.ParsePrefix(cfg.FakeIPRange6)
		if err != nil {
			return nil, err
		}
		if !dnsCfg.FakeIPRange6.Addr().Is6() {
			return nil, errors.New("dns.fake-ip-range6 must be a IPv6 prefix")
		}
	}

	if cfg.EnhancedMode == C.DNSFakeIP {
		var fakeIPTrie *trie.DomainTrie[struct{}]
		if len(dnsCfg.Fallback) != 0 {
			fakeIPTrie = trie.New[struct{}]()
			for _, fb := range dnsCfg.Fallback {
				if net.ParseIP(fb.Addr) != nil {
					continue
				}
				_ = fakeIPTrie.Insert(fb.Addr, struct{}{})
			}
		}

		skipper := &fakeip.Skipper{Mode: cfg.FakeIPFilterMode}

		if cfg.FakeIPFilterMode == C.FilterRule {
			rules, err := parseFakeIPRules(cfg.FakeIPFilter, ruleProviders)
			if err != nil {
				return nil, err
			}
			skipper.Rules = rules
		} else {
			host, err := parseDomain(cfg.FakeIPFilter, fakeIPTrie, "dns.fake-ip-filter", ruleProviders)
			if err != nil {
				return nil, err
			}
			skipper.Host = host
		}

		dnsCfg.FakeIPSkipper = skipper
		dnsCfg.FakeIPTTL = cfg.FakeIPTTL

		if dnsCfg.FakeIPRange.IsValid() {
			pool, err := fakeip.New(fakeip.Options{
				IPNet:       dnsCfg.FakeIPRange,
				Size:        1000,
				Persistence: rawCfg.Profile.StoreFakeIP,
			})
			if err != nil {
				return nil, err
			}
			dnsCfg.FakeIPPool = pool
		}

		if dnsCfg.FakeIPRange6.IsValid() {
			pool6, err := fakeip.New(fakeip.Options{
				IPNet:       dnsCfg.FakeIPRange6,
				Size:        1000,
				Persistence: rawCfg.Profile.StoreFakeIP,
			})
			if err != nil {
				return nil, err
			}
			dnsCfg.FakeIPPool6 = pool6
		}

		if dnsCfg.FakeIPPool == nil && dnsCfg.FakeIPPool6 == nil {
			return nil, errors.New("disallow `fake-ip-range` and `fake-ip-range6` both empty with fake-ip mode")
		}
	}

	if len(cfg.Fallback) != 0 {
		if cfg.FallbackFilter.GeoIP {
			matcher, err := RC.NewGEOIP(cfg.FallbackFilter.GeoIPCode, "dns.fallback-filter.geoip", false, true)
			if err != nil {
				return nil, fmt.Errorf("load GeoIP dns fallback filter error, %w", err)
			}
			dnsCfg.FallbackIPFilter = append(dnsCfg.FallbackIPFilter, matcher.DnsFallbackFilter())
		}
		if len(cfg.FallbackFilter.IPCIDR) > 0 {
			cidrSet := cidr.NewIpCidrSet()
			for idx, ipcidr := range cfg.FallbackFilter.IPCIDR {
				err = cidrSet.AddIpCidrForString(ipcidr)
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %w", idx, err)
				}
			}
			err = cidrSet.Merge()
			if err != nil {
				return nil, err
			}
			matcher := cidrSet // dns.fallback-filter.ipcidr
			dnsCfg.FallbackIPFilter = append(dnsCfg.FallbackIPFilter, matcher)
		}
		if len(cfg.FallbackFilter.Domain) > 0 {
			domainTrie := trie.New[struct{}]()
			for idx, domain := range cfg.FallbackFilter.Domain {
				err = domainTrie.Insert(domain, struct{}{})
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackDomain[%d] format error: %w", idx, err)
				}
			}
			matcher := domainTrie.NewDomainSet() // dns.fallback-filter.domain
			dnsCfg.FallbackDomainFilter = append(dnsCfg.FallbackDomainFilter, matcher)
		}
		if len(cfg.FallbackFilter.GeoSite) > 0 {
			log.Warnln("replace fallback-filter.geosite with nameserver-policy, it will be removed in the future")
			for idx, geoSite := range cfg.FallbackFilter.GeoSite {
				matcher, err := RC.NewGEOSITE(geoSite, "dns.fallback-filter.geosite")
				if err != nil {
					return nil, fmt.Errorf("DNS FallbackGeosite[%d] format error: %w", idx, err)
				}
				dnsCfg.FallbackDomainFilter = append(dnsCfg.FallbackDomainFilter, matcher)
			}
		}
	}

	return dnsCfg, nil
}

func parseFakeIPRules(rawRules []string, ruleProviders map[string]P.RuleProvider) ([]C.Rule, error) {
	var rules []C.Rule

	for idx, line := range rawRules {
		tp, payload, action, params := RC.ParseRulePayload(line, true)

		action = strings.ToLower(action)
		if action != fakeip.UseFakeIP && action != fakeip.UseRealIP {
			return nil, fmt.Errorf("dns.fake-ip-filter[%d] [%s] error: invalid action '%s', must be 'fake-ip' or 'real-ip'", idx, line, action)
		}

		if tp == "RULE-SET" {
			if rp, ok := ruleProviders[payload]; !ok {
				return nil, fmt.Errorf("dns.fake-ip-filter[%d] [%s] error: rule-set '%s' not found", idx, line, payload)
			} else {
				switch rp.Behavior() {
				case P.IPCIDR:
					return nil, fmt.Errorf("dns.fake-ip-filter[%d] [%s] error: rule-set behavior is %s, must be domain or classical", idx, line, rp.Behavior())
				case P.Classical:
					log.Warnln("%s provider is %s, only matching domain rules in fake-ip-filter", rp.Name(), rp.Behavior())
				default:
				}
			}
		}

		parsed, err := R.ParseRule(tp, payload, action, params, nil)
		if err != nil {
			return nil, fmt.Errorf("dns.fake-ip-filter[%d] [%s] error: %w", idx, line, err)
		}

		if !isDomainRule(parsed.RuleType()) && parsed.RuleType() != C.MATCH {
			return nil, fmt.Errorf("dns.fake-ip-filter[%d] [%s] error: rule type '%s' not supported, only domain-based rules allowed", idx, line, tp)
		}

		rules = append(rules, parsed)
	}

	return rules, nil
}

func isDomainRule(rt C.RuleType) bool {
	switch rt {
	case C.Domain, C.DomainSuffix, C.DomainKeyword, C.DomainRegex, C.DomainWildcard, C.GEOSITE, C.RuleSet:
		return true
	default:
		return false
	}
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

func parseIPV6(rawCfg *RawConfig) {
	if !rawCfg.IPv6 || !verifyIP6() {
		rawCfg.DNS.FakeIPRange6 = ""
		rawCfg.Tun.Inet6Address = nil
	}
}

func parseTun(rawTun RawTun, dns *DNS, general *General) error {
	tunAddressPrefix := dns.FakeIPRange
	if !tunAddressPrefix.IsValid() {
		tunAddressPrefix = netip.MustParsePrefix("198.18.0.1/16")
	}
	tunAddressPrefix = netip.PrefixFrom(tunAddressPrefix.Addr(), 30)

	general.Tun = LC.Tun{
		Enable:              rawTun.Enable,
		Device:              rawTun.Device,
		Stack:               rawTun.Stack,
		DNSHijack:           rawTun.DNSHijack,
		AutoRoute:           rawTun.AutoRoute,
		AutoDetectInterface: rawTun.AutoDetectInterface,

		MTU:                                   rawTun.MTU,
		GSO:                                   rawTun.GSO,
		GSOMaxSize:                            rawTun.GSOMaxSize,
		Inet4Address:                          []netip.Prefix{tunAddressPrefix},
		Inet6Address:                          rawTun.Inet6Address,
		IPRoute2TableIndex:                    rawTun.IPRoute2TableIndex,
		IPRoute2RuleIndex:                     rawTun.IPRoute2RuleIndex,
		AutoRedirect:                          rawTun.AutoRedirect,
		AutoRedirectInputMark:                 rawTun.AutoRedirectInputMark,
		AutoRedirectOutputMark:                rawTun.AutoRedirectOutputMark,
		AutoRedirectIPRoute2FallbackRuleIndex: rawTun.AutoRedirectIPRoute2FallbackRuleIndex,
		LoopbackAddress:                       rawTun.LoopbackAddress,
		StrictRoute:                           rawTun.StrictRoute,
		RouteAddress:                          rawTun.RouteAddress,
		RouteAddressSet:                       rawTun.RouteAddressSet,
		RouteExcludeAddress:                   rawTun.RouteExcludeAddress,
		RouteExcludeAddressSet:                rawTun.RouteExcludeAddressSet,
		IncludeInterface:                      rawTun.IncludeInterface,
		ExcludeInterface:                      rawTun.ExcludeInterface,
		IncludeUID:                            rawTun.IncludeUID,
		IncludeUIDRange:                       rawTun.IncludeUIDRange,
		ExcludeUID:                            rawTun.ExcludeUID,
		ExcludeUIDRange:                       rawTun.ExcludeUIDRange,
		ExcludeSrcPort:                        rawTun.ExcludeSrcPort,
		ExcludeSrcPortRange:                   rawTun.ExcludeSrcPortRange,
		ExcludeDstPort:                        rawTun.ExcludeDstPort,
		ExcludeDstPortRange:                   rawTun.ExcludeDstPortRange,
		IncludeAndroidUser:                    rawTun.IncludeAndroidUser,
		IncludePackage:                        rawTun.IncludePackage,
		ExcludePackage:                        rawTun.ExcludePackage,
		EndpointIndependentNat:                rawTun.EndpointIndependentNat,
		UDPTimeout:                            rawTun.UDPTimeout,
		DisableICMPForwarding:                 rawTun.DisableICMPForwarding,
		FileDescriptor:                        rawTun.FileDescriptor,

		Inet4RouteAddress:        rawTun.Inet4RouteAddress,
		Inet6RouteAddress:        rawTun.Inet6RouteAddress,
		Inet4RouteExcludeAddress: rawTun.Inet4RouteExcludeAddress,
		Inet6RouteExcludeAddress: rawTun.Inet6RouteExcludeAddress,

		RecvMsgX: rawTun.RecvMsgX,
		SendMsgX: rawTun.SendMsgX,
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

func parseSniffer(snifferRaw RawSniffer, ruleProviders map[string]P.RuleProvider) (*sniffer.Config, error) {
	snifferConfig := &sniffer.Config{
		Enable:          snifferRaw.Enable,
		ForceDnsMapping: snifferRaw.ForceDnsMapping,
		ParsePureIp:     snifferRaw.ParsePureIp,
	}
	loadSniffer := make(map[snifferTypes.Type]sniffer.SnifferConfig)

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
					loadSniffer[snifferType] = sniffer.SnifferConfig{
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
		if snifferConfig.Enable && len(snifferRaw.Sniffing) != 0 {
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
					loadSniffer[snifferType] = sniffer.SnifferConfig{
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

	snifferConfig.Sniffers = loadSniffer

	forceDomain, err := parseDomain(snifferRaw.ForceDomain, nil, "sniffer.force-domain", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in force-domain, error:%w", err)
	}
	snifferConfig.ForceDomain = forceDomain

	skipSrcAddress, err := parseIPCIDR(snifferRaw.SkipSrcAddress, nil, "sniffer.skip-src-address", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-src-address, error:%w", err)
	}
	snifferConfig.SkipSrcAddress = skipSrcAddress

	skipDstAddress, err := parseIPCIDR(snifferRaw.SkipDstAddress, nil, "sniffer.skip-dst-address", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-dst-address, error:%w", err)
	}
	snifferConfig.SkipDstAddress = skipDstAddress

	skipDomain, err := parseDomain(snifferRaw.SkipDomain, nil, "sniffer.skip-domain", ruleProviders)
	if err != nil {
		return nil, fmt.Errorf("error in skip-domain, error:%w", err)
	}
	snifferConfig.SkipDomain = skipDomain

	return snifferConfig, nil
}

func parseIPCIDR(addresses []string, cidrSet *cidr.IpCidrSet, adapterName string, ruleProviders map[string]P.RuleProvider) (matchers []C.IpMatcher, err error) {
	var matcher C.IpMatcher
	for _, ipcidr := range addresses {
		ipcidrLower := strings.ToLower(ipcidr)
		if strings.HasPrefix(ipcidrLower, "geoip:") {
			subkeys := strings.Split(ipcidr, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, country := range subkeys {
				matcher, err = RC.NewGEOIP(country, adapterName, false, false)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else if strings.HasPrefix(ipcidrLower, "rule-set:") {
			subkeys := strings.Split(ipcidr, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, domainSetName := range subkeys {
				matcher, err = parseIPRuleSet(domainSetName, adapterName, ruleProviders)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else {
			if cidrSet == nil {
				cidrSet = cidr.NewIpCidrSet()
			}
			err = cidrSet.AddIpCidrForString(ipcidr)
			if err != nil {
				return nil, err
			}
		}
	}
	if !cidrSet.IsEmpty() {
		err = cidrSet.Merge()
		if err != nil {
			return nil, err
		}
		matcher = cidrSet
		matchers = append(matchers, matcher)
	}
	return
}

func parseDomain(domains []string, domainTrie *trie.DomainTrie[struct{}], adapterName string, ruleProviders map[string]P.RuleProvider) (matchers []C.DomainMatcher, err error) {
	var matcher C.DomainMatcher
	for _, domain := range domains {
		domainLower := strings.ToLower(domain)
		if strings.HasPrefix(domainLower, "geosite:") {
			subkeys := strings.Split(domain, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, country := range subkeys {
				matcher, err = RC.NewGEOSITE(country, adapterName)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else if strings.HasPrefix(domainLower, "rule-set:") {
			subkeys := strings.Split(domain, ":")
			subkeys = subkeys[1:]
			subkeys = strings.Split(subkeys[0], ",")
			for _, domainSetName := range subkeys {
				matcher, err = parseDomainRuleSet(domainSetName, adapterName, ruleProviders)
				if err != nil {
					return nil, err
				}
				matchers = append(matchers, matcher)
			}
		} else {
			if domainTrie == nil {
				domainTrie = trie.New[struct{}]()
			}
			err = domainTrie.Insert(domain, struct{}{})
			if err != nil {
				return nil, err
			}
		}
	}
	if !domainTrie.IsEmpty() {
		matcher = domainTrie.NewDomainSet()
		matchers = append(matchers, matcher)
	}
	return
}

func parseIPRuleSet(domainSetName string, adapterName string, ruleProviders map[string]P.RuleProvider) (C.IpMatcher, error) {
	if rp, ok := ruleProviders[domainSetName]; !ok {
		return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
	} else {
		switch rp.Behavior() {
		case P.Domain:
			return nil, fmt.Errorf("rule provider type error, except ipcidr,actual %s", rp.Behavior())
		case P.Classical:
			log.Warnln("%s provider is %s, only matching it contain ip rule", rp.Name(), rp.Behavior())
		default:
		}
	}
	return RP.NewRuleSet(domainSetName, adapterName, false, true)
}

func parseDomainRuleSet(domainSetName string, adapterName string, ruleProviders map[string]P.RuleProvider) (C.DomainMatcher, error) {
	if rp, ok := ruleProviders[domainSetName]; !ok {
		return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
	} else {
		switch rp.Behavior() {
		case P.IPCIDR:
			return nil, fmt.Errorf("rule provider type error, except domain,actual %s", rp.Behavior())
		case P.Classical:
			log.Warnln("%s provider is %s, only matching it contain domain rule", rp.Name(), rp.Behavior())
		default:
		}
	}
	return RP.NewRuleSet(domainSetName, adapterName, false, true)
}
