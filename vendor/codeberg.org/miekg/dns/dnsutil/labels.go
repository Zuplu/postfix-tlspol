package dnsutil

import (
	"iter"
	"strings"
)

// Join joins the labels in s to form a fully qualified domain name.
func Join(ls ...string) string {
	if len(ls) == 0 {
		return ""
	}

	if ls[len(ls)-1] == "." {
		return Fqdn(strings.Join(ls[:len(ls)-1], "."))
	}
	return Fqdn(strings.Join(ls, "."))
}

// Split splits the name s in its labels. See [Forward] and [Next] for allocationless alternatives.
func Split(s string) []string {
	if s == "." {
		return []string{"."}
	}

	if IsFqdn(s) {
		return strings.Split(s[:len(s)-1], ".")
	}
	return strings.Split(s, ".")
}

// Forward allows ranging over an name s on a per label basis. The empty string returns nothing a single root
// label returns only that label. See [Next].
func Forward(s string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if s == "" {
			return
		}
		if s == "." {
			yield(".")
			return
		}

		offset := 0
		for {
			offset1, end := Next(s, offset)
			if !yield(s[offset : offset1-1]) {
				return
			}
			if end {
				return
			}

			offset = offset1
		}
	}
}

// Backward allows ranging over an name s on a per label basis in reverse. The empty string returns nothing, a single root
// label returns only that label. See [Prev].
func Backward(s string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if s == "" {
			return
		}
		if s == "." {
			yield(".")
			return
		}

		offset := len(s)
		for {
			offset1, end := Prev(s, offset)
			if !yield(s[offset1 : offset-1]) {
				return
			}
			if end {
				return
			}

			offset = offset1
		}
	}
}
