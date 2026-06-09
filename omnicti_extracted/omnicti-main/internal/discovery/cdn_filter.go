package discovery

import (
	"net"
)

var cdnRanges = []string{
	// Cloudflare (sample subset)
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/12",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// Add other CDNs like Akamai, Fastly here
}

var cidrs []*net.IPNet

func init() {
	for _, cidr := range cdnRanges {
		_, netCIDR, err := net.ParseCIDR(cidr)
		if err == nil {
			cidrs = append(cidrs, netCIDR)
		}
	}
}

// FilterCDN removes IPs that belong to known CDN providers.
// This is critical to avoid false positives (attributing Cloudflare's vulnerabilities to the target).
func FilterCDN(ips []net.IP) []net.IP {
	var filtered []net.IP
	for _, ip := range ips {
		isCDN := false
		for _, network := range cidrs {
			if network.Contains(ip) {
				isCDN = true
				break
			}
		}
		if !isCDN {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}
