package common

import "bytes"

func InsertStringEveryNth(str string, insert string, n int) string {
	var buffer bytes.Buffer

	for i, rune := range str {
		buffer.WriteRune(rune)

		if i%n == n-1 && i != len(str)-1 {
			buffer.WriteString(insert)
		}
	}

	return buffer.String()
}
