package pwned

type PasteResp struct {
	Source     string `json:"Source"`
	Id         string `json:"Id"`
	Title      string `json:"Title"`
	Date       string `json:"Date"`
	EmailCount int    `json:"EmailCount"`
}
