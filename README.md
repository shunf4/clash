<h1 align="center">
  <img src="https://github.com/Dreamacro/clash/raw/master/docs/logo.png" alt="Clash" width="200">
  <br>Clash<br>
</h1>

<h4 align="center">A rule-based tunnel in Go. [shunf4 fork]</h4>

<p align="center">
  <a href="https://github.com/Dreamacro/clash/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Dreamacro/clash/release.yml?branch=master&style=flat-square" alt="Github Actions">
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

This is a general overview of the features that comes with Clash.  

- Inbound: HTTP, HTTPS, SOCKS5 server, TUN device
- Outbound: Shadowsocks(R), VMess, Trojan, Snell, SOCKS5, HTTP(S), Wireguard
- Rule-based Routing: dynamic scripting, domain, IP addresses, process name and more
- Fake-IP DNS: minimises impact on DNS pollution and improves network performance
- Transparent Proxy: Redirect TCP and TProxy TCP/UDP with automatic route table/rule management
- Proxy Groups: automatic fallback, load balancing or latency testing
- Remote Providers: load remote proxy lists dynamically
- RESTful API: update configuration in-place via a comprehensive API

*Some of the features may only be available in the [Premium core](https://dreamacro.github.io/clash/premium/introduction.html).*

## Documentation

You can find the latest documentation at [https://dreamacro.github.io/clash/](https://dreamacro.github.io/clash/).

## Credits

- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)

## License

This software is released under the GPL-3.0 license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2FDreamacro%2Fclash.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2FDreamacro%2Fclash?ref=badge_large)
