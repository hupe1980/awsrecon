package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// nolint gosec only a testsecret
var testSecret = "AKIAIOSFODNN7EXAMPLE  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func TestScanner(t *testing.T) {
	t.Run("no verify", func(t *testing.T) {
		scanner := Scanner{}

		result, err := scanner.Scan(context.TODO(), false, testSecret)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result))
		assert.Equal(t, "AWSAccessKey", result[0].ID)
	})
}
