package dnsutil

// Common compares the names a and b and returns how many labels they have in common starting
// from the *right*. The comparison stops at the first inequality. For example:
//
//   - www.miek.nl. and miek.nl. have two labels in common: miek and nl
//   - www.miek.nl. and www.bla.nl. have one label in common: nl
//   - . and . have no labels in common.
//
// a and b must be syntactically valid domain names, see [IsName] and [IsFqdn].
func Common(a, b string) (n int) {
	// copy-ish of CompareName
	if a == "." || b == "." { // shortcut root, as we would return 1
		return 0
	}

	lasta := len(a)
	lastb := len(b)
	for {
		cura, overshota := Prev(a, lasta)
		curb, overshotb := Prev(b, lastb)
		x := compareLabel(a[cura:lasta-1], b[curb:lastb-1])
		if x != 0 {
			return n
		}
		n++
		if overshota || overshotb {
			return n
		}
		lasta = cura
		lastb = curb
	}
}
