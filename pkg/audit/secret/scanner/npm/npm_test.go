package npm

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// nolint gosec only a testsecret
var testSecret = "npm_6mOgrBdoVZuWywSBAYBX2ATgdwi9MO50w1y8"

type MockClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func TestScanner(t *testing.T) {
	t.Run("no verify", func(t *testing.T) {
		scanner := Scanner{
			HTTPClient: http.DefaultClient,
		}

		result, err := scanner.Scan(context.TODO(), false, testSecret)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result))
		assert.Equal(t, "NPMToken", result[0].ID)
		assert.Equal(t, testSecret, result[0].Raw)
		assert.Equal(t, false, result[0].Verified)
	})

	t.Run("verified", func(t *testing.T) {
		scanner := Scanner{
			HTTPClient: &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(nil)),
					}, nil
				},
			},
		}

		result, err := scanner.Scan(context.TODO(), true, testSecret)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result))
		assert.Equal(t, "NPMToken", result[0].ID)
		assert.Equal(t, testSecret, result[0].Raw)
		assert.Equal(t, true, result[0].Verified)
	})

	t.Run("not verified", func(t *testing.T) {
		scanner := Scanner{
			HTTPClient: &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusForbidden,
						Body:       io.NopCloser(bytes.NewReader(nil)),
					}, nil
				},
			},
		}

		result, err := scanner.Scan(context.TODO(), true, testSecret)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result))
		assert.Equal(t, "NPMToken", result[0].ID)
		assert.Equal(t, testSecret, result[0].Raw)
		assert.Equal(t, false, result[0].Verified)
	})
}
