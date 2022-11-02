package audit

import (
	"math"
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
		assert.Equal(t, true, withinTolerance(1.584962500721156, entropy, 1e-12))
	})
}

func withinTolerance(a, b, e float64) bool {
	if a == b {
		return true
	}

	d := math.Abs(a - b)

	if b == 0 {
		return d < e
	}

	return (d / math.Abs(b)) < e
}
