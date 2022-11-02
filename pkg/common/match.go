package common

// WildcardMatch reports whether the text matches/satisfies the pattern string.
// '*' and '?' wildcards are supported.
func WildcardMatch(pattern, name string) (matched bool) {
	if pattern == "" {
		return name == pattern
	}

	if pattern == "*" {
		return true
	}

	return deepMatchRune([]rune(name), []rune(pattern))
}

func deepMatchRune(str, pattern []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '?':
			if len(str) == 0 {
				return false
			}
		case '*':
			return deepMatchRune(str, pattern[1:]) || (len(str) > 0 && deepMatchRune(str[1:], pattern))
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		}

		str = str[1:]
		pattern = pattern[1:]
	}

	return len(str) == 0 && len(pattern) == 0
}
