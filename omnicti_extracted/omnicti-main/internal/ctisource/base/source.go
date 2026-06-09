package base

import (
	"context"

	"domainscorer/internal/normalize"
)

type Source interface {
	Name() string
	Fetch(ctx context.Context, target string) (any, error)
	Map(raw any, asset string) ([]normalize.Finding, error)
}
