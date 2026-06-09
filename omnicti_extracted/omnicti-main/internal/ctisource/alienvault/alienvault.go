package alienvault

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
	return "alienvault"
}

func (s *Source) Fetch(ctx context.Context, target string) (any, error) {
	return Fetch(ctx, target)
}

func (s *Source) Map(raw any, asset string) ([]normalize.Finding, error) {
	// Cast raw to expecting map type if needed, or let Map handle it
	rawMap, ok := raw.(map[string]any)
	if !ok {
		return nil, nil
	}

	f := Map(rawMap, asset)
	if f == nil {
		return nil, nil
	}
	return []normalize.Finding{*f}, nil
}
