package pwned

import (
	"encoding/json"
	"fmt"
	//"net/http"
	"testing"
	//	"time"
)

func TestNewClient(t *testing.T) {
	c := NewClient(nil, "test@example.com")
	req, _ := c.NewRequest("GET", "breaches/", nil)
	res, e := c.do(req, nil)
	if e != nil {
		fmt.Println("error", e)
	}
	fmt.Println(req.UserAgent())
	var response []BreachResp
	err := json.Unmarshal([]byte(res), &response)
	t.Log(response)
	if err != nil {
		fmt.Println(err)
	}
	body, _ := json.MarshalIndent(response, "", "    ")
	t.Log(fmt.Sprintf("%s", body))
}
