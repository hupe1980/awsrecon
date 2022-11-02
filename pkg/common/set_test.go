package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSet(t *testing.T) {
	t.Run("ToSlice", func(t *testing.T) {
		set := SetOf("a", "b", "c", "b")

		assert.ElementsMatch(t, []string{"a", "b", "c"}, set.ToSlice())
	})
}
