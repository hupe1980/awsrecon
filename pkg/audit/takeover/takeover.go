package takeover

import (
	"net/http"
	"strings"
)

type Engine struct {
	httpClient   *http.Client
	fingerprints []Fingerprint
	verify       bool
}

func New(verify bool) *Engine {
	return &Engine{
		httpClient:   http.DefaultClient,
		fingerprints: DefaultFingerprints,
		verify:       verify,
	}
}

type CheckCnameOutput struct {
	Service  string
	Verified bool
}

func (e *Engine) CheckCName(cname string) *CheckCnameOutput {
	for _, fingerprint := range e.fingerprints {
		for _, c := range fingerprint.CName {
			if strings.Contains(cname, c) {
				return &CheckCnameOutput{
					Service:  fingerprint.Service,
					Verified: false,
				}
			}
		}
	}

	return nil
}
