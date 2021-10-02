//go:build linux
// +build linux

package netparam

import (
	"bufio"
	"encoding/binary"
	"github.com/Dreamacro/clash/log"
	"net"
	"os"
	"strconv"
	"strings"
)

func GetDhcpNameservers() (nameservers []string, domain string, searchs []string) {
	// Not implemented
	log.Warnln("GetDhcpNameservers() is not implemented on linux")
	return []string{}, "", []string{}
}

func GetGateways() (gateways []string) {

	f, err := os.Open("/proc/net/route")
	if err != nil {
		log.Warnln("GetGateways: open /proc/net/route failed: %s", err.Error())
		return []string{}
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	// Go to the second line
	s.Scan()
	s.Scan()

	// Get gateway (hex ip address) and cast to uint32
	d, err := strconv.ParseInt("0x"+strings.Split(s.Text(), "\t")[2], 0, 64)
	if err != nil {
		log.Warnln("GetGateways: parse hex ip error: %s", err.Error())
		return []string{}
	}
	d32 := uint32(d)

	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, d32)

	return []string{ip.String()}
}
