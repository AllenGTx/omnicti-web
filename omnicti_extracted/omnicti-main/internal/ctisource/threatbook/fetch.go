package threatbook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

func Fetch(ctx context.Context, domain string) (map[string]any, error) {
	// 1. Resolve Domain to IP
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for domain %s", domain)
	}

	// Pick first IPv4
	var targetIP string
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip.String()
			break
		}
	}
	if targetIP == "" {
		targetIP = ips[0].String()
	}

	// 2. Call ThreatBook API
	req, _ := http.NewRequestWithContext(
		ctx,
		"GET",
		"https://api.threatbook.cn/v3/scene/ip_reputation",
		nil,
	)

	q := req.URL.Query()
	q.Add("resource", targetIP)
	q.Add("lang", "en")
	q.Add("apikey", os.Getenv("THREATBOOK_KEY"))
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ThreatBook API error: %s - %s", resp.Status, string(bodyBytes))
	}

	var out map[string]any
	err = json.NewDecoder(resp.Body).Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
