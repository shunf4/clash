//go:build windows
// +build windows

package netparam

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"

	"github.com/metacubex/mihomo/log"
	"golang.org/x/sys/windows"
)

// This file replaces the powershell invocations that used to live in
// netparam_windows.go (a Find-NetRoute lookup for the default route plus a
// Win32_NetworkAdapter query for its GUID).
//
// GetBestRoute2 covers the default route lookup (InterfaceIndex + NextHop) and
// GetAdaptersAddresses covers InterfaceIndex -> adapter GUID.
//
// GetBestRoute2 is not exported by golang.org/x/sys, so it is bound here and
// the returned MIB_IPFORWARD_ROW2 is read from a byte buffer with explicit
// offsets. That keeps the Win32 layout independent from Go's field alignment
// rules (SOCKADDR_INET is a union whose alignment Go would otherwise miss).

const (
	// MIB_IPFORWARD_ROW2 offsets/size, see
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2
	//   NET_LUID          InterfaceLuid        0  (8, aligned 8)
	//   NET_IFINDEX       InterfaceIndex       8  (4)
	//   IP_ADDRESS_PREFIX DestinationPrefix   12  (SOCKADDR_INET 28 + PrefixLength 1, padded to 32)
	//   SOCKADDR_INET     NextHop             44  (28)
	//   ... UCHAR SitePrefixLength(72) ... Origin(100..104)
	rowOffsetInterfaceIndex = 8
	rowOffsetPrefixLength   = 40 // DestinationPrefix.PrefixLength
	rowOffsetNextHop        = 44
	mibIpForwardRow2Size    = 104

	sockaddrInetSize = 28 // sizeof(SOCKADDR_INET), the IPv6 member is the largest
)

type defaultInterface struct {
	ifIndex uint32
	guid    string
	gateway string
}

var procGetBestRoute2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")

// getDefaultInterface returns the interface index, the adapter GUID and the
// next hop of the default route, i.e. the route for destination 0.0.0.0, which
// is what Find-NetRoute -RemoteIPAddress 0.0.0.0 resolves.
func getDefaultInterface() (*defaultInterface, error) {
	// Surface a missing export as an error instead of letting LazyProc.Call panic.
	if err := procGetBestRoute2.Find(); err != nil {
		return nil, err
	}

	destination := make([]byte, sockaddrInetSize)
	binary.LittleEndian.PutUint16(destination[0:], windows.AF_INET) // sin_family, sin_addr stays 0.0.0.0

	// The next hop is extracted from the row after the call returns.
	row := make([]byte, mibIpForwardRow2Size)
	bestSource := make([]byte, sockaddrInetSize)

	r1, _, _ := procGetBestRoute2.Call(
		0,                                       // InterfaceLuid (NULL)
		0,                                       // InterfaceIndex
		0,                                       // SourceAddress (NULL)
		uintptr(unsafe.Pointer(&destination[0])), // DestinationAddress
		0,                                       // AddressSortOptions
		uintptr(unsafe.Pointer(&row[0])),        // BestRoute
		uintptr(unsafe.Pointer(&bestSource[0])), // BestSourceAddress
	)
	if r1 != 0 {
		return nil, syscall.Errno(r1)
	}

	ifIndex := binary.LittleEndian.Uint32(row[rowOffsetInterfaceIndex:])
	family := binary.LittleEndian.Uint16(row[12:]) // DestinationPrefix.Prefix.si_family
	prefixLen := row[rowOffsetPrefixLength]        // 0 for a default route
	gateway := nextHopIP(row[rowOffsetNextHop : rowOffsetNextHop+sockaddrInetSize])

	guid, err := interfaceGUID(ifIndex)
	if err != nil {
		return nil, err
	}

	// Comparison aid for validating the replacement against the old powershell
	// implementation; remove once verified on a real machine.
	log.Debugln("[netparam] getDefaultInterface(): ifIndex=%d guid=%s nextHop=%q dstFamily=%d dstPrefixLen=%d",
		ifIndex, guid, gateway, family, prefixLen)

	iface := &defaultInterface{ifIndex: ifIndex, guid: guid, gateway: gateway}
	return iface, nil
}

// nextHopIP returns the IPv4 next hop of a route. A route on the local link
// has a zeroed next hop, in which case "" is returned.
func nextHopIP(sockaddr []byte) string {
	if binary.LittleEndian.Uint16(sockaddr[0:]) != windows.AF_INET {
		return ""
	}
	var addr [4]byte
	copy(addr[:], sockaddr[4:8]) // sin_port(2) + sin_addr(4)
	if addr == [4]byte{} {
		return ""
	}
	return net.IP(addr[:]).String()
}

// interfaceGUID returns the "{XXXXXXXX-XXXX-...}" adapter GUID for an
// interface index. GetAdaptersAddresses' AdapterName is exactly that string and
// is also the name of the adapter key under Tcpip\Parameters\Interfaces.
func interfaceGUID(ifIndex uint32) (string, error) {
	if ifIndex == 0 {
		return "", errors.New("invalid interface index 0")
	}
	aas, err := adapterAddresses()
	if err != nil {
		return "", err
	}
	for _, aa := range aas {
		if aa.AdapterName == nil {
			continue
		}
		if aa.IfIndex == ifIndex || aa.Ipv6IfIndex == ifIndex {
			return windows.BytePtrToString(aa.AdapterName), nil
		}
	}
	return "", errors.New("no adapter matches interface index")
}

func adapterAddresses() ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	for {
		b = make([]byte, l)
		const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err != syscall.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
		if l <= uint32(len(b)) {
			return nil, err
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}
