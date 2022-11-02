package slack

import (
	"context"
	"encoding/json"
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
	regex = map[string]*regexp.Regexp{
		"SlackBotToken":              regexp.MustCompile(`xoxb\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
		"SlackUserToken":             regexp.MustCompile(`xoxp\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
		"SlackWorkspaceAccessToken":  regexp.MustCompile(`xoxa\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
		"SlackWorkspaceRefreshToken": regexp.MustCompile(`xoxr\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*`),
	}
	verifyURL = "https://slack.com/api/auth.test"
)

type authRes struct {
	Ok     bool   `json:"ok"`
	URL    string `json:"url"`
	Team   string `json:"team"`
	User   string `json:"user"`
	TeamID string `json:"team_id"`
	UserID string `json:"user_id"`
	BotID  string `json:"bot_id"`
	Error  string `json:"error"`
}

func (s Scanner) Keywords() []string {
	return []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-"}
}

func (s Scanner) Scan(ctx context.Context, verify bool, data string) ([]scanner.Result, error) {
	results := []scanner.Result{}

	for id, r := range regex {
		matches := r.FindAllString(data, -1)

		for _, match := range matches {
			r := scanner.Result{
				ID:       id,
				Raw:      match,
				Verified: false,
			}

			if verify {
				req, err := http.NewRequestWithContext(ctx, "POST", verifyURL, nil)
				if err != nil {
					continue
				}

				req.Header.Add("Content-Type", "application/json; charset=utf-8")
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", match))

				if res, err := s.HTTPClient.Do(req); err == nil {
					defer res.Body.Close()

					var authResponse authRes
					if err := json.NewDecoder(res.Body).Decode(&authResponse); err != nil {
						continue
					}

					r.Verified = authResponse.Ok
				}
			}

			results = append(results, r)
		}
	}

	return results, nil
}
