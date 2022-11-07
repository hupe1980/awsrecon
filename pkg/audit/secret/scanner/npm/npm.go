package npm

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hupe1980/awsrecon/pkg/audit/secret/scanner"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Scanner struct {
	HTTPClient HTTPClient
}

var (
	regex = regexp.MustCompile(`(npm_[0-9a-zA-Z]{36})`)
)

func (s Scanner) Keywords() []string {
	return []string{"npm_"}
}

func (s Scanner) Scan(ctx context.Context, verify bool, data string) ([]scanner.Result, error) {
	results := []scanner.Result{}

	matches := regex.FindAllStringSubmatch(data, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}

		resMatch := match[1]

		r := scanner.Result{
			ID:       "NPMToken",
			Raw:      resMatch,
			Verified: false,
		}

		if verify {
			req, err := http.NewRequestWithContext(ctx, "GET", "https://registry.npmjs.org/-/whoami", nil)
			if err != nil {
				continue
			}

			req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", resMatch))

			res, err := s.HTTPClient.Do(req)
			if err == nil {
				defer res.Body.Close()

				if res.StatusCode >= 200 && res.StatusCode < 300 {
					r.Verified = true
				}
			}
		}

		results = append(results, r)
	}

	return results, nil
}
