package scanner

import "context"

type Result struct {
	ID       string
	Verified bool
	Raw      string
}

type Scanner interface {
	Keywords() []string
	Scan(ctx context.Context, verify bool, data string) ([]Result, error)
}
