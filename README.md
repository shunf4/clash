<h1 align="center">
  <img src="https://github.com/Dreamacro/clash/raw/master/docs/logo.png" alt="Clash" width="200">
  <br>Clash<br>
</h1>

<h4 align="center">A rule-based tunnel in Go. [shunf4 fork]</h4>

<p align="center">
  <a href="https://github.com/Dreamacro/clash/actions">
    <img src="https://img.shields.io/github/workflow/status/Dreamacro/clash/Go?style=flat-square" alt="Github Actions">
  </a>
  <a href="https://goreportcard.com/report/github.com/Dreamacro/clash">
    <img src="https://goreportcard.com/badge/github.com/Dreamacro/clash?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/Dreamacro/clash?style=flat-square">
  <a href="https://github.com/Dreamacro/clash/releases">
    <img src="https://img.shields.io/github/release/Dreamacro/clash/all.svg?style=flat-square">
  </a>
  <a href="https://github.com/Dreamacro/clash/releases/tag/premium">
    <img src="https://img.shields.io/badge/release-Premium-00b4f0?style=flat-square">
  </a>
</p>

## Shunf4's Fork Added Features

You can add the following special "nameserver" URI to use some system network configuration entries in Clash's built-in DNS server:

#### `special://dynamic-system-resolve-client`

Clash will add a name resolve client alongside other nameservers. This client, when called, will always query the local system for the name (using `net.ResolveIPAddr` in Golang), and pass the result back.

This is useful when you want name query result from your local network in Clash's name resolution.

**Note: when using this special nameserver, do not set Clash's built in server as your system's resolver!**

#### `special://dynamic-dhcp-nameservers-client`

Clash will add a name resolve client alongside other nameservers. This client, when called, will always find current DNS server address(es) **that is acquired from DHCP server (no matter what is set as the local system's resolver)**, query them for the name, and pass the result back.

This is useful when you want name query result from your local network in Clash's name resolution, and you want to set Clash as your system's resolver.

**Not implemented on linux.**

#### `special://dynamic-gateways-client`

Clash will add a name resolve client alongside other nameservers. This client, when called, will always find current **default gateway address(es)**, treat them as DNS server, query them for the name, and pass the result back.

This is useful when you want name query result from your local network (that is possible to be statically configured) in Clash's name resolution, and you want to set Clash as your system's resolver.

#### `special://static-system-nameservers-on-clash-start`

When Clash started, it acquires current system's DNS resolvers **once**, and add them to built-in DNS server's upstream nameservers.

#### `special://static-dhcp-nameservers-on-clash-start`

When Clash started, it acquires DNS resolvers that is from the current network's DHCP resolver **once**, and add them to built-in DNS server's upstream nameservers.

**Not implemented on linux.**

#### `special://static-gateways-on-clash-start`

When Clash started, it acquires current gateway address(es) **once**, and add them to built-in DNS server's upstream nameservers.


## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- VMess, Shadowsocks, Trojan, Snell protocol support for remote connections
- Built-in DNS server that aims to minimize DNS pollution attack impact, supports DoH/DoT upstream and fake IP.
- Rules based off domains, GEOIP, IPCIDR or Process to forward packets to different nodes
- Remote groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select node based off latency
- Remote providers, allowing users to get node lists remotely instead of hardcoding in config
- Netfilter TCP redirecting. Deploy Clash on your Internet gateway with `iptables`.
- Comprehensive HTTP RESTful API controller

## Premium Features

- TUN mode on macOS, Linux and Windows. [Doc](https://github.com/Dreamacro/clash/wiki/premium-core-features#tun-device)
- Match your tunnel by [Script](https://github.com/Dreamacro/clash/wiki/premium-core-features#script)
- [Rule Provider](https://github.com/Dreamacro/clash/wiki/premium-core-features#rule-providers)

## Getting Started
Documentations are now moved to [GitHub Wiki](https://github.com/Dreamacro/clash/wiki).

## Premium Release
[Release](https://github.com/Dreamacro/clash/releases/tag/premium)

## Development
If you want to build an application that uses clash as a library, check out the the [GitHub Wiki](https://github.com/Dreamacro/clash/wiki/use-clash-as-a-library)

## Credits

* [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
* [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)

## License

This software is released under the GPL-3.0 license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_large)
