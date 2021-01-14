// +build linux

package dns

import (
	"golang.org/x/sys/windows/registry"
)

func GetCurrDhcpNameservers() (nameservers []string, domain string, searchs []string) {
	// Not implemented
	return []string{}, "", []string{}
}