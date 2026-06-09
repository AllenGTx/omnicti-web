package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type ShodanResponse struct {
	Matches []struct {
		IPStr     string                 `json:"ip_str"`
		Port      int                    `json:"port"`
		Domains   []string               `json:"domains"`
		Hostnames []string               `json:"hostnames"`
		Data      string                 `json:"data"`
		Product   string                 `json:"product"`
		Vulns     map[string]interface{} `json:"vulns"` // Map of CVE -> summary
		Timestamp string                 `json:"timestamp"`
	} `json:"matches"`
	Total int `json:"total"`
}

func (s *Source) Fetch(ctx context.Context, target string) (any, error) {
	apiKey := os.Getenv("SHODAN_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("skipped: SHODAN_KEY not set")
	}

	// Search for the domain or IP
	// Use search/host endpoint? Or generic query?
	// Generic query "hostname:example.com" tends to be good for domains.
	// For IPs, we can use /shodan/host/{ip}.
	// Given the blueprint "For every IP/domain... Shodan service exposure + verified CVE",
	// let's use the search API with hostname for domains.

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=hostname:%s", apiKey, target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized (invalid SHODAN_KEY)")
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited (plan quota exceeded)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error %d", resp.StatusCode)
	}

	var out ShodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	return out.Matches, nil
}
