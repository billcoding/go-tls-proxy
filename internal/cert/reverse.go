package cert

import (
	"fmt"
	"net"
	"strings"
)

// reversePointer 返回 RFC 8738 要求放进 TLS SNI 的反向域名。
func reversePointer(ip net.IP) (string, error) {
	if ip == nil {
		return "", fmt.Errorf("无效 IP")
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v4[3], v4[2], v4[1], v4[0]), nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", fmt.Errorf("无效 IP %s", ip)
	}
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "%x.%x.", v6[i]&0x0f, v6[i]>>4)
	}
	b.WriteString("ip6.arpa")
	return b.String(), nil
}

func challengeNames(ip net.IP) ([]string, error) {
	ptr, err := reversePointer(ip)
	if err != nil {
		return nil, err
	}
	return []string{ptr, ip.String()}, nil
}
