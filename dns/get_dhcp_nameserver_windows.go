// +build windows

package dns

import (
	"golang.org/x/sys/windows/registry"
)

func GetCurrDhcpNameservers() (nameservers []string, domain string, searchs []string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
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