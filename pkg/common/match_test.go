package common

import "testing"

func TestWildcardMatch(t *testing.T) {
	testCases := []struct {
		pattern string
		text    string
		matched bool
	}{
		{
			pattern: "*",
			text:    "s3:GetObject",
			matched: true,
		},
		{
			pattern: "s3:Get*",
			text:    "s3:GetObject",
			matched: true,
		},
	}

	for i, testCase := range testCases {
		actualResult := WildcardMatch(testCase.pattern, testCase.text)
		if testCase.matched != actualResult {
			t.Errorf("Test %d: Expected the result to be `%v`, but instead found it to be `%v`", i+1, testCase.matched, actualResult)
		}
	}
}
