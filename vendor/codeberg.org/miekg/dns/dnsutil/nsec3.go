package dnsutil

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"

	"codeberg.org/miekg/dns/internal/pack"
)

// NSEC3Name returns the hashed owner name according to RFC 5155. The hash is always SHA-1, the only algorithm
// RFC 5155 defines; when hashing a name for comparison with an NSEC3 record, check that record's Hash field
// first.
func NSEC3Name(s, salt string, iter uint16) string {
	hashdata := make([]byte, hex.DecodedLen(len(salt))+255)
	n, err := pack.Name(s, hashdata, 0, nil, false)
	if err != nil {
		return ""
	}
	m, err := pack.StringHex(salt, hashdata[n:], 0)
	if err != nil {
		return ""
	}
	hashdata = hashdata[:n+m]

	hash := sha1.New()
	// k = 0
	hash.Write(hashdata)
	nsec3 := hash.Sum(nil)

	for range iter {
		hash.Reset()
		hash.Write(nsec3)
		hash.Write(hashdata[n:])
		nsec3 = hash.Sum(nil)
	}
	return base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(nsec3)
}
