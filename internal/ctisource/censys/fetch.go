package censys

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
)

type Source struct{}

func NewSource() *Source {
	return &Source{}
}

// ---------------------------------------------------------
// Censys Platform V3 Host Structure
// ---------------------------------------------------------

type V3HostResponse struct {
	Code   int      `json:"code"`
	Status string   `json:"status"`
	Result V3Result `json:"result"`
}

type V3Result struct {
	Resource V3Resource `json:"resource"`
}

type V3Resource struct {
	IP       string      `json:"ip"`
	Services []V3Service `json:"services"`
}

type V3Service struct {
	Port              int    `json:"port"`
	Protocol          string `json:"protocol"`           // e.g. "HTTP", "SSH"
	TransportProtocol string `json:"transport_protocol"` // e.g. "tcp"
	ScanTime          string `json:"scan_time"`

	// Protocol specific details are nested keys
	TLS  *V3TLS  `json:"tls,omitempty"`
	HTTP *V3HTTP `json:"http,omitempty"`
}

type V3TLS struct {
	FingerprintSHA256 string        `json:"fingerprint_sha256"`
	PresentedChain    []V3CertChain `json:"presented_chain,omitempty"`
}

type V3CertChain struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	SubjectDN         string `json:"subject_dn"`
	IssuerDN          string `json:"issuer_dn"`
}

type V3HTTP struct {
	URI        string `json:"uri"`
	Protocol   string `json:"protocol"`
	StatusCode int    `json:"status_code"`
	Server     string `json:"server"`
}

// ---------------------------------------------------------
// Engine
// ---------------------------------------------------------

func (s *Source) Fetch(ctx context.Context, target string) (any, error) {
	apiID := os.Getenv("CENSYS_API_ID")
	apiSecret := os.Getenv("CENSYS_API_SECRET")
	if apiID == "" || apiSecret == "" {
		return nil, fmt.Errorf("skipped: CENSYS_API_ID or CENSYS_API_SECRET not set")
	}

	// 1. Resolve Domain to IPs
	// The V3 Asset API requires an IP address. It does not search by domain.
	// We must resolve the domain to find its current IPs.
	ips, err := net.LookupIP(target)
	if err != nil {
		// return nil, fmt.Errorf("dns resolution failed: %w", err)
		// Don't fail the whole scan if DNS fails, just return empty
		return nil, nil
	}

	if len(ips) == 0 {
		return nil, nil
	}

	var wg sync.WaitGroup
	var results []V3Resource
	var mu sync.Mutex

	// 2. Fetch Host Details for each IP
	for _, ip := range ips {
		// Only supporting IPv4 for now as per typical Censys usage
		if ip.To4() == nil {
			continue
		}

		wg.Add(1)
		go func(ipStr string) {
			defer wg.Done()

			res, err := s.fetchHostV3(ctx, apiSecret, ipStr)
			if err != nil {
				// Log but don't stop others
				// fmt.Printf("DEBUG: Failed to fetch %s: %v\n", ipStr, err)
				return
			}

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(ip.String())
	}

	wg.Wait()

	if len(results) == 0 {
		// return nil, fmt.Errorf("no hosts found")
		return nil, nil // Return empty finding list is safer
	}

	return map[string]any{
		"v3_hosts": results,
		// No separate certs search in this V3 asset path unless we do a separate search call
		// But user auth fails for Search API (V2).
		// So we rely purely on what we see on the Host.
	}, nil
}

func (s *Source) fetchHostV3(ctx context.Context, secret, ip string) (V3Resource, error) {
	// Endpoint: https://api.platform.censys.io/v3/global/asset/host/{ip}
	url := fmt.Sprintf("https://api.platform.censys.io/v3/global/asset/host/%s", ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return V3Resource{}, err
	}

	// V3 Auth is strictly Bearer if using the secret provided by user?
	// User example: --header 'Authorization: Bearer censys_...'
	// We'll use Bearer logic.

	// Ensure secret is cleaned?
	// If user put "censys_..." in secret, we use it directly.
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.censys.api.v3.host.v1+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return V3Resource{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// IP not found in Censys
		return V3Resource{}, fmt.Errorf("not found")
	}
	if resp.StatusCode == 401 {
		fmt.Fprintf(os.Stderr, "[!] Warning: Censys V3 401 Unauthorized for IP %s\n", ip)
		return V3Resource{}, fmt.Errorf("unauthorized")
	}
	if resp.StatusCode != 200 {
		return V3Resource{}, fmt.Errorf("http status %d", resp.StatusCode)
	}

	var out V3HostResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return V3Resource{}, err
	}

	return out.Result.Resource, nil
}

func (s *Source) Name() string {
	return "censys"
}
