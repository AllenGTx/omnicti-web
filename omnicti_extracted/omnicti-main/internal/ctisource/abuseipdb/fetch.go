package abuseipdb

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
	// AbuseIPDB requires an IP address, so we must resolve the domain first.
	ips, err := net.LookupIP(domain)
	if err != nil {
		// If we can't resolve it, we can't check it against AbuseIPDB.
		// Returning nil error means we just don't have findings for this source.
		// Alternatively, we could return the error to warn the user.
		// For now, let's wrap it so the engine knows but doesn't crash.
		return nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for domain %s", domain)
	}

	// Pick the first IPv4 if possible, otherwise first IP
	var targetIP string
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip.String()
			break
		}
	}
	if targetIP == "" && len(ips) > 0 {
		targetIP = ips[0].String()
	}

	// 2. Call AbuseIPDB API
	req, _ := http.NewRequestWithContext(
		ctx,
		"GET",
		"https://api.abuseipdb.com/api/v2/check",
		nil,
	)

	q := req.URL.Query()
	q.Add("ipAddress", targetIP)
	q.Add("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Key", os.Getenv("ABUSEIPDB_KEY"))
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("AbuseIPDB API error: %s - %s", resp.Status, string(bodyBytes))
	}

	var out map[string]any
	err = json.NewDecoder(resp.Body).Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
