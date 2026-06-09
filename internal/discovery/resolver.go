package discovery

import "net"

// Resolve performs a DNS lookup to retrieve the IP addresses for a given domain.
// It returns a slice of net.IP.
func Resolve(domain string) ([]net.IP, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}

	out := []net.IP{}
	for _, ip := range ips {
		// Prefer IPv4 for now as CTI tools mostly focus on it, but we can keep both.
		// The blueprint example shows IPv4.
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4)
		}
	}
	return out, nil
}
