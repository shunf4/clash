// +build windows

package dns

import (
	"os/exec"
	"strings"

	"github.com/Dreamacro/clash/log"
	"golang.org/x/sys/windows/registry"
)

func GetCurrDhcpNameservers() (nameservers []string, domain string, searchs []string) {
	out, err := exec.Command("powershell", "-command", "$ifi=Find-NetRoute -RemoteIPAddress 0.0.0.0|Select InterfaceIndex -Last 1|Select -ExpandProperty InterfaceIndex;Get-WmiObject Win32_NetworkAdapter -Filter InterfaceIndex=$ifi|Select-Object -ExpandProperty GUID").Output()
	if err != nil {
		log.Warnln("GetCurrDhcpNameservers() powershell: %s", err.Error())
		return []string{}, "", []string{}
	}

	outStr := strings.TrimSpace(string(out))

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + outStr, registry.QUERY_VALUE)
	if err != nil {
		return []string {}, "", []string {}
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