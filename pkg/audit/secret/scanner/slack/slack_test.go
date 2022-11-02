package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// nolint gosec only a testsecret
var testSecret = "xoxb-263594206564-2343594206574-FGqddMF8t08v8N7Oq4i57vs1MBS"

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
		assert.Equal(t, "SlackBotToken", result[0].ID)
	})

	t.Run("verified", func(t *testing.T) {
		scanner := Scanner{
			HTTPClient: &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					responseBody, err := newResponseBody(true)
					if err != nil {
						t.Fail()
					}

					return &http.Response{
						StatusCode: 200,
						Body:       responseBody,
					}, nil
				},
			},
		}

		result, err := scanner.Scan(context.TODO(), true, testSecret)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result))
		assert.Equal(t, "SlackBotToken", result[0].ID)
		assert.Equal(t, true, result[0].Verified)
	})

	t.Run("not verified", func(t *testing.T) {
		scanner := Scanner{
			HTTPClient: &MockClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					responseBody, err := newResponseBody(false)
					if err != nil {
						t.Fail()
					}

					return &http.Response{
						StatusCode: 200,
						Body:       responseBody,
					}, nil
				},
			},
		}

		result, err := scanner.Scan(context.TODO(), true, testSecret)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result))
		assert.Equal(t, "SlackBotToken", result[0].ID)
		assert.Equal(t, false, result[0].Verified)
	})
}

func newResponseBody(verify bool) (io.ReadCloser, error) {
	authRes := &authRes{
		Ok: verify,
	}

	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(authRes); err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(b.Bytes())), nil
}
