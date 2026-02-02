package utils

import "slices"

func Reverse(s string) string {
	a := []rune(s)
	slices.Reverse(a)
	return string(a)
}
