package secret

import (
	"context"
	"net/http"
	"strings"

	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner"
	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner/aws"
	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner/npm"
	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner/privatekey"
	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner/slack"
)

type Engine struct {
	scanners []scanner.Scanner
	verify   bool
}

func NewEngine(verify bool) *Engine {
	httpClient := http.DefaultClient

	return &Engine{
		scanners: []scanner.Scanner{
			&aws.Scanner{},
			&npm.Scanner{
				HTTPClient: httpClient,
			},
			&privatekey.Scanner{},
			&slack.Scanner{
				HTTPClient: httpClient,
			},
		},
		verify: verify,
	}
}

func (e *Engine) Scan(data string) []string {
	findings := []string{}

	for _, scanner := range e.scanners {
		foundKeyword := false

		for _, kw := range scanner.Keywords() {
			if strings.Contains(strings.ToLower(data), strings.ToLower(kw)) {
				foundKeyword = true
				break
			}
		}

		if !foundKeyword {
			continue
		}

		results, err := scanner.Scan(context.TODO(), e.verify, data)
		if err != nil {
			print(err)
			continue
		}

		for _, result := range results {
			findings = append(findings, result.ID)
		}
	}

	return findings
}
