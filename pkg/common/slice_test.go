package common

import "testing"

func TestSliceContains(t *testing.T) {
	testCases := []struct {
		slice    []string
		value    string
		contains bool
	}{
		{
			slice:    []string{"a", "b", "c"},
			value:    "b",
			contains: true,
		},
		{
			slice:    []string{"a", "b", "c"},
			value:    "d",
			contains: false,
		},
	}

	for i, testCase := range testCases {
		actualResult := SliceContains(testCase.slice, testCase.value)
		if testCase.contains != actualResult {
			t.Errorf("Test %d: Expected the result to be `%v`, but instead found it to be `%v`", i+1, testCase.contains, actualResult)
		}
	}
}

func TestSliceContainsSubslice(t *testing.T) {
	testCases := []struct {
		slice    []string
		subslice []string
		contains bool
	}{
		{
			slice:    []string{"a", "b", "c"},
			subslice: []string{"b", "c"},
			contains: true,
		},
		{
			slice:    []string{"a", "b", "c"},
			subslice: []string{"a", "b", "c"},
			contains: true,
		},
		{
			slice:    []string{"a", "b", "c"},
			subslice: []string{"c", "d"},
			contains: false,
		},
		{
			slice:    []string{"a", "b", "c"},
			subslice: []string{"d", "e"},
			contains: false,
		},
	}

	for i, testCase := range testCases {
		actualResult := SliceContainsSubslice(testCase.slice, testCase.subslice)
		if testCase.contains != actualResult {
			t.Errorf("Test %d: Expected the result to be `%v`, but instead found it to be `%v`", i+1, testCase.contains, actualResult)
		}
	}
}
