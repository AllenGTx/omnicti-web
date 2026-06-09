package leakix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type DomainResponse struct {
	Services []map[string]interface{} `json:"Services"`
	Leaks    []map[string]interface{} `json:"Leaks"`
}

func (s *Source) Fetch(ctx context.Context, domain string) (any, error) {
	// Note: LeakIX free API has limits and might require an API key for some endpoints or higher rate limits.
	// Using the domain endpoint as per blueprint.
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("https://leakix.net/domain/%s", domain),
		nil,
	)
	if err != nil {
		return nil, err
	}

	// Check for API key (Optional but recommended for limits)
	key := os.Getenv("LEAKIX_KEY")
	if key != "" {
		req.Header.Set("api-key", key)
	} else {
		// Log hint? Or just proceed. For transparency, maybe we don't error but we could note it?
		// But since we want "error handling", let's focus on HTTP errors.
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		// OK
	case 429:
		return nil, fmt.Errorf("rate limited (429)")
	case 403, 401:
		return nil, fmt.Errorf("unauthorized (check LEAKIX_KEY)")
	default:
		return nil, fmt.Errorf("http error %d", resp.StatusCode)
	}

	var out DomainResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	// We return the Leaks part as that's what we are interested in for this scorer
	// But technically we could return the whole object if we wanted services too.
	// Blueprint says "LeakIX misconfiguration & leaks".
	return out.Leaks, nil
}
