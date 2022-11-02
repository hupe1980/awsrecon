package common

func SliceContains[T comparable](slice []T, v T) bool {
	for _, s := range slice {
		if v == s {
			return true
		}
	}

	return false
}

func SliceContainsSubslice[T comparable](slice []T, sub []T) bool {
	if len(sub) > len(slice) {
		return false
	}

	for _, e := range sub {
		if !SliceContains(slice, e) {
			return false
		}
	}

	return true
}
