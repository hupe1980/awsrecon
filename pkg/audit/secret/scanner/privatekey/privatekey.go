package privatekey

import (
	"context"
	"regexp"

	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner"
)

type Scanner struct{}

var (
	regex = regexp.MustCompile(`(?i)-----\s*?BEGIN[ A-Z0-9_-]*?PRIVATE KEY\s*?-----[\s\S]*?----\s*?END[ A-Z0-9_-]*? PRIVATE KEY\s*?-----`)
)

func (s Scanner) Keywords() []string {
	return []string{"private key"}
}

func (s Scanner) Scan(_ context.Context, _ bool, data string) ([]scanner.Result, error) {
	results := []scanner.Result{}

	matches := regex.FindAllString(data, -1)

	for _, match := range matches {
		token := normalize(match)

		if len(token) < 64 {
			continue
		}

		r := scanner.Result{
			ID:       "PrivateKey",
			Raw:      token,
			Verified: false,
		}

		results = append(results, r)
	}

	return results, nil
}
