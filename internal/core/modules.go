package core

import (
	"context"
	"domainscorer/internal/normalize"
)

type Module interface {
	Name() string
	Run(ctx context.Context, t Target) ([]normalize.Finding, error)
}
