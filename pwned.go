package pwned

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const pwdURL string = "https://api.pwnedpasswords.com/"
const userAgent string = "haveIBeenPwned"
const NumberOfHash int = 5

// Check if password is compromised
func IsPasswordCompromised(password string) (bool, error) {
	if password == "" {
		return false, errors.New("Value for compromised check cannot be empty")
	}
	// SHA1 for generation of hash
	hashed := getHash(password)

	// first 5 charaters of hash
	hashPrefix := strings.ToUpper(hashed[:5])
	hashSuffix := strings.ToUpper(hashed[5:])

	r := fmt.Sprintf("range/%s", hashPrefix)
	url := fmt.Sprintf(pwdURL+"%s", r)

	res, err := getData(url)
	if err != nil {
		return false, err
	}
	response := strings.Split(string(res), "\r\n")
	for _, target := range response {
		if len(target) < 35 {
			return false, nil
		}
		if string(target[:35]) == hashSuffix {
			_, err := strconv.ParseInt(target[36:], 10, 64)
			if err != nil {
				return false, err
			}
			return true, err
		}
	}
	return false, nil
}

// Client interface
func getData(url string) ([]byte, error) {
	c := NewClient(nil, userAgent)
	req, err := c.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, err
	}
	res, err := c.do(req, nil)
	if err != nil {
		return []byte{}, err
	}
	return res, nil
}
