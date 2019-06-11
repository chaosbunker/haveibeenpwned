package pwned

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const baseURL string = "https://haveibeenpwned.com/api/v2/"
const pwdURL string = "https://api.pwnedpasswords.com/"
const userAgent string = "IhaveBeenPwned"
const NumberOfHash int = 5

// Returns all breaches or breaches for an account
func GetBreach(parameter, service, domain, truncateResponse, includeUnverified string) ([]BreachResp, string, error) {

	var url string
	var response []BreachResp

	switch service {
	case "breachedaccount/":
		u := service + parameter + "?truncateResponse=" + truncateResponse + "&&includeUnverified=" + includeUnverified
		url = fmt.Sprintf(baseURL+"%s", u)
		if domain != "" {
			// build url for getting breaches for an account on a specific domain
			url = fmt.Sprintf(url + "&&domain=" + domain)
		}
	case "breaches/":
		if domain == "" {
			url = fmt.Sprintf(baseURL+"%s", service)
		} else {
			url = fmt.Sprintf(baseURL+"%s", service+"?domain="+domain)
		}
	}
	res, err := getData(url)
	if err != nil {
		return response, "", err
	}

	err = json.Unmarshal(res, &response)

	if err != nil {
		return response, "", err
	}

	body, _ := json.MarshalIndent(response, "", "    ")

	return response, fmt.Sprintf("%s", body), nil
}

func GetSingleBreach(parameter, service, domain, truncateResponse, includeUnverified string) (BreachResp, string, error) {

	var url string
	var response BreachResp

	url = fmt.Sprintf(baseURL+"%s", service+domain)
	res, err := getData(url)
	if err != nil {
		return response, "", err
	}
	err = json.Unmarshal(res, &response)

	if err != nil {
		return response, "", err
	}
	body, _ := json.MarshalIndent(response, "", "    ")

	return response, fmt.Sprintf("%s", body), nil
}

// Returns all data classes in the system
func GetDataClasses(parameter, service, domain string) ([]string, string, error) {
	url := fmt.Sprintf(baseURL+"%s", service)

	res, err := getData(url)
	if err != nil {
		return []string{}, "", err
	}
	var response []string
	err = json.Unmarshal(res, &response)
	if err != nil {
		return []string{}, "", err
	}

	body, _ := json.MarshalIndent(response, "", "    ")

	return response, fmt.Sprintf("%s", body), nil
}

// Returns all pastes for an account
func GetPasteAccount(parameter, service, domain string) ([]PasteResp, string, error) {
	url := fmt.Sprintf(baseURL+"%s", service+parameter)

	res, err := getData(url)
	if err != nil {
		return []PasteResp{}, "", err
	}
	var response []PasteResp
	err = json.Unmarshal(res, &response)
	if err != nil {
		return []PasteResp{}, "", err
	}

	body, _ := json.MarshalIndent(response, "", "    ")
	return response, fmt.Sprintf("%s", body), nil
}

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
