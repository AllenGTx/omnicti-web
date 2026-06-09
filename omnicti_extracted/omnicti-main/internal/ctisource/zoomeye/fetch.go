package zoomeye

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func Fetch(ctx context.Context, domain string) (map[string]any, error) {
	// ZoomEye V2 API (AI)
	url := "https://api.zoomeye.ai/v2/search"

	// Query: hostname:<domain>
	// V2 uses POST with JSON body for search
	query := fmt.Sprintf("hostname:%s", domain)
	payload := map[string]any{
		"qbase64": base64.StdEncoding.EncodeToString([]byte(query)),
		"page":    1,
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	req.Header.Set("API-KEY", os.Getenv("ZOOMEYE_KEY"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body for error parsing
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		// Try to parse error message explicitly
		var errResp map[string]any
		if json.Unmarshal(respBytes, &errResp) == nil {
			if msg, ok := errResp["message"].(string); ok {
				return nil, fmt.Errorf("zoomeye api error: %s (code: %v)", msg, errResp["code"])
			}
		}
		return nil, fmt.Errorf("zoomeye api returned status: %d", resp.StatusCode)
	}

	var out map[string]any
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, err
	}

	return out, nil
}
