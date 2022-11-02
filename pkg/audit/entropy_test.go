package audit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShannonEntropy(t *testing.T) {
	t.Run("aaa", func(t *testing.T) {
		entropy := ShannonEntropy("aaa")
		assert.Equal(t, 0.0, entropy)
	})

	t.Run("aaabbb", func(t *testing.T) {
		entropy := ShannonEntropy("aaabbb")
		assert.Equal(t, 1.0, entropy)
	})

	t.Run("aaabbbccc", func(t *testing.T) {
		entropy := ShannonEntropy("aaabbbccc")
		assert.Equal(t, 1.5849625007211563, entropy)
	})
}
