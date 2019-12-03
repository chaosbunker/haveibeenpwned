package pwned

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

func getHash(value string) string {
	alg := sha1.New()
	alg.Write([]byte(value))
	return strings.ToUpper(hex.EncodeToString(alg.Sum(nil)))
}
