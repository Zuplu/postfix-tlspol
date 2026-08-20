package dnsutil

type skip uint

const (
	SkipForward skip = iota + 1
	SkipBackward
)

// Skip skips n labels in s in the desired direction. If the returned bool is true then beginning
// the name was reached if this is the case s is returned as-is.
func Skip(s string, n int, direction skip) (string, bool) {
	switch direction {
	case SkipForward:
		var i, end = 0, false
		for range n {
			i, end = Next(s, i)
			if end {
				break
			}
		}
		return s[i:], end
	case SkipBackward:
		var i, start = len(s), false
		for range n {
			i, start = Prev(s, i)
			if start {
				break
			}
		}
		return s[i:], start
	}
	panic("never reached")
}
