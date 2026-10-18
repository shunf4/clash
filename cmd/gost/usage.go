package gost

// usage is printed by -h/--help and on argument errors.
const usage = `Usage:
  mhm gost -L <inbound> [-F <outbound>] [options]
  mhm gost [options] '<yaml fragment>'

Flags:
  -L <inbound>     inbound listener: URL (socks5h://, socks5://, http://, mixed://, ...)
                   or a YAML fragment with a "type" key
  -F <outbound>    upstream outbound, omitted means direct internet access;
                   the same two forms are accepted
  --disk=deny|allow  (default deny)  allow mihomo to write to the disk
  --net=deny|allow   (default deny)  allow mihomo initiated network access
  --dry-run          print the generated configuration and exit
  -h, --help         show this help

Both -L and -F accept a URL or a multi-line YAML fragment. Quote the fragment for
your shell (usually single quotes), or use @file to read it from a file. Query
parameters of URL forms use the same names as the matching mihomo configuration
fields; nested fields use dots, e.g. ws-opts.path=/ws or reality-opts.public-key=...
The inbound also accepts the aliases -l/--listen, the outbound -f/--forward.

URL forms (written to be human friendly, aligned with common share links):
  -L socks5h://[user:pass@]host:port?udp=true
  -L http://[user:pass@]host:port
  -L mixed://[user:pass@]host:port
  -F ss://cipher:password@host:port?udp=true&plugin=obfs-local;obfs=http;obfs-host=x
  -F socks5h://[user:pass@]host:port
  -F http://[user:pass@]host:port
  -F trojan://password@host:port?sni=x&network=ws&ws-opts.path=/p
  -F vless://uuid@host:port?security=tls&sni=x&type=grpc&serviceName=svc
  -F hy2://password@host:port?sni=x&obfs=salamander&obfs-password=y
  -F tuic://uuid:password@host:port?congestion_control=bbr
  -F anytls://password@host:port?sni=x
  -F snell://psk@host:port?version=4
  -F ssh://user:pass@host:22
  -F wireguard://private-key@host:51820?ip=10.0.0.2&public-key=...
  -F masque://private-key@host:443?public-key=...
  -F sudoku://key@host:8443?http-mask=true
  -F mieru://user:pass@host:port?transport=tcp
  -F direct://   reject://
  -F vmess://<base64 share link>    (accepted, prefer the URL or YAML form)
  -F ssr://<base64 share link>      (accepted, prefer the URL or YAML form)

Any other mihomo outbound type can be written as a YAML fragment, for example:
  -F 'type: wireguard
server: example.com
port: 51820
private-key: ...
ip: 10.0.0.2
public-key: ...'

YAML fragments are merged with mihomo defaults, validated by the same decoders
as the regular configuration and shown in --dry-run. Unknown keys are reported
and ignored.

Defaults chosen for a minimal setup: mode global (or direct when -F is omitted),
log-level info (every proxied connection is logged), ipv6 on, find-process-mode
off, allow-lan off, profile.store-selected off, no rules (the listener is bound
to the single outbound), UDP enabled for socks/mixed (a warning about UDP
exposure is printed at startup).

Examples:
  mhm gost -L socks5h://127.0.0.1:1080
  mhm gost -L socks5h://127.0.0.1:1080 -F ss://aes-128-gcm:secret@192.0.2.10:8388
  mhm gost -L mixed://127.0.0.1:7890 -F @upstream.yaml
`
