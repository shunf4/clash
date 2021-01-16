// +build windows

package dns

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

func determineSplitChar(s string) string {
	if strings.Index(s, " ") >= 0 {
		return " "
	}
	if strings.Index(s, ",") >= 0 {
		return ","
	}
	return " "
}

func splitStringToList(nsss string) []string {
	if nsss == "" {
		return []string{}
	}
	splitChar := determineSplitChar(nsss)
	return strings.Split(nsss, splitChar)
}

func GetCurrLocalResolver() (nameservers []string, domain string, searchs []string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE)
	if err != nil {
		return []string {}, "", []string {}
	}
	
	defer k.Close()

	var nsss string = ""

	nsss, _, err = k.GetStringValue("NameServer")
	if err != nil {
		nsss = ""
	}
	if nsss != "" {
		domain, _, err = k.GetStringValue("Domain")
		if err != nil {
			domain = ""
		}
	} else {
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
	}

	sss, _, err := k.GetStringValue("SearchList")
	if err != nil {
		sss = ""
	}

	return splitStringToList(nsss), domain, splitStringToList(sss)
}