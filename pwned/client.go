package pwned

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type Client struct {
	UserAgent string

	httpClient *http.Client
}

// Load server cert and create client object
func NewClient(httpClient *http.Client, ua string) *Client {
	if httpClient == nil {
		caCert, err := ioutil.ReadFile("ca.cer")
		if err != nil {
			log.Fatal(err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caCertPool,
				},
			},
		}
	}

	c := &Client{httpClient: httpClient, UserAgent: ua}
	return c
}

// Creates new http request object
func (c *Client) NewRequest(method, url string, body interface{}) (*http.Request, error) {
	buf := new(bytes.Buffer)
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	//req.Header.Set("Accept", "application/vnd.haveibeenpwned.v2+json")
	req.Header.Add("User-Agent", c.UserAgent)
	return req, nil
}

func (c *Client) do(req *http.Request, v interface{}) ([]byte, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if http.StatusOK != resp.StatusCode {
		return nil, fmt.Errorf("Unexpected API response status: %v", resp.StatusCode)
	}
	return body, nil
}
