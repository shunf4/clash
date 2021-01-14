// +build darwin

package dns

import (
	"os/exec"
	"strings"

	"github.com/Dreamacro/clash/log"
)

func isLineDelimiter(r rune) bool {
	return r == '\n' || r == '\r'
}

func isFieldDelimiter(r rune) bool {
	return r == '\t' || r == ' ' || r == ':'
}

func isNameserversFieldDelimiter(r rune) bool {
	return r == '\t' || r == ' ' || r == ':' || r == '{' || r == '}' || r == ','
}

func GetCurrDhcpNameservers() (nameservers []string, domain string, searchs []string) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		log.Warnln("GetCurrDhcpNameservers() route: %s", err.Error())
		return []string{}, "", []string{}
	}

	outStr := string(out)
	outLines := strings.FieldsFunc(outStr, isLineDelimiter)

	interfaceName := ""
	for _, l := range outLines {
		fields := strings.FieldsFunc(l, isFieldDelimiter)
		if len(fields) >= 2 && fields[0] == "interface" {
			interfaceName = fields[1]
			break
		}
	}

	if interfaceName == "" {
		return []string{}, "", []string{}
	}

	out2, err := exec.Command("ipconfig", "getpacket", interfaceName).Output()
	if err != nil {
		log.Warnln("GetCurrDhcpNameservers() ipconfig getpacket: %s", err.Error())
		return []string{}, "", []string{}
	}

	outStr2 := string(out2)
	outLines2 := strings.FieldsFunc(outStr2, isLineDelimiter)

	nameservers = []string{}
	domain = ""
	searchs = []string{}

	for _, l := range outLines2 {
		fields := strings.Split(l, ":")
		stripped := strings.TrimSpace(fields[0])
		if len(fields) >= 2 && strings.Contains(stripped, "domain_name_server") {
			nameserversStr := fields[1]
			nameservers = strings.FieldsFunc(nameserversStr, isNameserversFieldDelimiter)
		}

		if len(fields) >= 2 && (strings.Contains(stripped, "domain_name ") || stripped == "domain_name") {
			domain = strings.TrimSpace(fields[1])
		}
	}

	return nameservers, domain, searchs
}
