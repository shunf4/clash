//go:build windows
// +build windows

package netparam

import (
	"os/exec"
	"strings"

	"github.com/metacubex/mihomo/log"
	"golang.org/x/sys/windows/registry"
)

func GetDhcpNameservers() (nameservers []string, domain string, searchs []string) {
	out, err := exec.Command("powershell", "-command", "$ifi=Find-NetRoute -RemoteIPAddress 0.0.0.0|Select InterfaceIndex -Last 1|Select -ExpandProperty InterfaceIndex;Get-WmiObject Win32_NetworkAdapter -Filter InterfaceIndex=$ifi|Select-Object -ExpandProperty GUID").Output()
	if err != nil {
		log.Warnln("GetDhcpNameservers() powershell: %s", err.Error())
		return []string{}, "", []string{}
	}

	outStr := strings.TrimSpace(string(out))

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+outStr, registry.QUERY_VALUE)
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
	out, err := exec.Command("powershell", "-command", "$ifi=Find-NetRoute -RemoteIPAddress 0.0.0.0|Select InterfaceIndex -Last 1|Select -ExpandProperty InterfaceIndex;Get-WmiObject Win32_NetworkAdapter -Filter InterfaceIndex=$ifi|Select-Object -ExpandProperty GUID").Output()
	if err != nil {
		log.Warnln("GetGateways() powershell: %s", err.Error())
		return []string{}
	}

	outStr := strings.TrimSpace(string(out))

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`+outStr, registry.QUERY_VALUE)
	if err != nil {
		return []string{}
	}

	defer k.Close()

	var gws []string = nil

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
