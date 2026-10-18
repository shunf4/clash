//go:build windows
// +build windows

package netparam

import (
	"time"

	"github.com/metacubex/mihomo/log"
	"golang.org/x/sys/windows/registry"
)

func GetDhcpNameservers() (nameservers []string, domain string, searchs []string) {
	start := time.Now()

	iface, err := getDefaultInterface()
	if err != nil {
		log.Warnln("GetDhcpNameservers() get default interface: %s", err.Error())
		return []string{}, "", []string{}
	}

	nameservers, domain, searchs = getDhcpNameserversFromRegistry(iface.guid)

	log.Debugln("[netparam] GetDhcpNameservers(): ifIndex=%d guid=%s nextHop=%q nameservers=%v domain=%q searchs=%v cost=%s",
		iface.ifIndex, iface.guid, iface.gateway, nameservers, domain, searchs, time.Since(start))
	return
}

func getDhcpNameserversFromRegistry(guid string) (nameservers []string, domain string, searchs []string) {
	if guid == "" {
		return []string{}, "", []string{}
	}

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+guid, registry.QUERY_VALUE)
	if err != nil {
		return []string{}, "", []string{}
	}

	defer k.Close()

	var nsss string = ""

	nsss, _, err = k.GetStringValue("DhcpNameServer")
	if err != nil {
		nsss = ""
	}
	if nsss != "" {
		domain, _, err = k.GetStringValue("DhcpDomain")
		if err != nil {
			domain = ""
		}
	}

	sss, _, err := k.GetStringValue("SearchList")
	if err != nil {
		sss = ""
	}

	return splitStringToList(nsss), domain, splitStringToList(sss)
}

func isNameserversEmpty(nameservers []string) bool {
	if nameservers == nil {
		return true
	}

	if len(nameservers) == 0 {
		return true
	}

	for _, n := range nameservers {
		if n != "" {
			return false
		}
	}

	return true
}

func filterEmptyString(s []string) []string {
	filtered := make([]string, 0)
	for _, v := range s {
		if v != "" {
			filtered = append(filtered, v)
		}
	}

	return filtered
}

func GetGateways() (gateways []string) {
	start := time.Now()

	iface, err := getDefaultInterface()
	if err != nil {
		log.Warnln("GetGateways() get default interface: %s", err.Error())
		return []string{}
	}

	// The next hop of the default route is its gateway unless the route is on
	// the local link (e.g. a TUN adapter), in which case fall back to the
	// registry values, as the previous implementation did.
	gateways = filterEmptyString([]string{iface.gateway})
	if len(gateways) == 0 {
		gateways = getGatewaysFromRegistry(iface.guid)
	}

	log.Debugln("[netparam] GetGateways(): ifIndex=%d guid=%s nextHop=%q gateways=%v cost=%s",
		iface.ifIndex, iface.guid, iface.gateway, gateways, time.Since(start))
	return gateways
}

func getGatewaysFromRegistry(guid string) (gws []string) {
	if guid == "" {
		return []string{}
	}

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+guid, registry.QUERY_VALUE)
	if err != nil {
		return []string{}
	}

	defer k.Close()

	gws, _, err = k.GetStringsValue("DefaultGateway")
	if err != nil {
		gws = nil
	}

	if isNameserversEmpty(gws) {
		gws, _, err = k.GetStringsValue("DhcpDefaultGateway")
		if err != nil {
			gws = nil
		}
	}

	if isNameserversEmpty(gws) {
		gws = []string{}
	}

	return filterEmptyString(gws)
}
