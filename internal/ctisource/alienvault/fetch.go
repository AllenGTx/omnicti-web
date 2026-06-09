package alienvault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

func Fetch(ctx context.Context, domain string) (map[string]any, error) {
	req, _ := http.NewRequestWithContext(
		ctx,
		"GET",
		fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/general", domain),
		nil,
	)
	req.Header.Set("X-OTX-API-KEY", os.Getenv("OTX_KEY"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	var out map[string]any
	err = json.NewDecoder(resp.Body).Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
