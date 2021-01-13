// +build !windows

package dns

import (
	"bufio"
	"os"
	"strings"
)

func GetCurrLocalResolver() (nameservers []string, domain string, searchs []string) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return []string{}, "", []string{}
	}

	defer f.Close()

	nameservers = []string{}
	domain = ""
	searchs = []string{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		if strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}

		tokens := strings.Fields(l)
		if len(tokens) < 2 {
			continue
		}
		
		if tokens[0] == "nameserver" {
			nameservers = append(nameservers, tokens[1])
		} else if tokens[0] == "domain" {
			domain = tokens[1]
			searchs = []string{}
		} else if tokens[0] == "search" {
			searchs = tokens[1:]
		}
	}

	if err := scanner.Err(); err != nil {
		return []string{}, "", []string{}
	}
	return nameservers, domain, searchs
}