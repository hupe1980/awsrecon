package aws

import (
	"context"
	"regexp"

	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner"
)

type Scanner struct{}

var (
	accessKeyRegex = regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`)
)

func (s Scanner) Keywords() []string {
	return []string{
		"AKIA",
		"ABIA",
		"ACCA",
		"ASIA",
	}
}

func (s Scanner) Scan(ctx context.Context, verify bool, data string) ([]scanner.Result, error) {
	results := []scanner.Result{}

	matches := accessKeyRegex.FindAllString(data, -1)

	for _, match := range matches {
		r := scanner.Result{
			ID:       "AWSAccessKey",
			Raw:      match,
			Verified: false,
		}

		results = append(results, r)
	}

	return results, nil
}
