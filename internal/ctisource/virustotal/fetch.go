package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// Minimal response structure for VT domain report
type VTResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats map[string]int `json:"last_analysis_stats"`
			LastAnalysisDate  int64          `json:"last_analysis_date"`
			Reputation        int            `json:"reputation"`
		} `json:"attributes"`
		Id string `json:"id"`
	} `json:"data"`
}

func (s *Source) Fetch(ctx context.Context, target string) (any, error) {
	key := os.Getenv("VIRUSTOTAL_KEY")
	if key == "" {
		return nil, fmt.Errorf("skipped: VIRUSTOTAL_KEY not set")
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("x-apikey", key)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil // Not found in VT is fine, not an error
	}
	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("rate limited (429)")
	}
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized (check VIRUSTOTAL_KEY)")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error %d", resp.StatusCode)
	}

	var out VTResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	return out, nil
}
