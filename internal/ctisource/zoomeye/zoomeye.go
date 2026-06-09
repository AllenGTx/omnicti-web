package zoomeye

import (
	"context"

	"domainscorer/internal/ctisource/base"
	"domainscorer/internal/normalize"
)

type Source struct{}

func NewSource() base.Source {
	return &Source{}
}

func (s *Source) Name() string {
	return "zoomeye"
}

func (s *Source) Fetch(ctx context.Context, target string) (any, error) {
	return Fetch(ctx, target)
}

func (s *Source) Map(raw any, asset string) ([]normalize.Finding, error) {
	rawMap, ok := raw.(map[string]any)
	if !ok {
		return nil, nil // Should handle null raw gracefully
	}
	return Map(rawMap, asset), nil
}
