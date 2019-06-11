package pwned

type BreachResp struct {
	Name         string   `json:"Name,omitempty"`
	Title        string   `json:"Title,omitempty"`
	Domain       string   `json:"Domain,omitempty"`
	BreachDate   string   `json:"BreachDate,omitempty"`
	AddedDate    string   `json:"AddedDate,omitempty"`
	ModifiedDate string   `json:"ModifiedDate,omitempty"`
	PwnCount     int      `json:"PwnCount,omitempty"`
	Description  string   `json:"Description,omitempty"`
	LogoPath     string   `json:"LogoPath,omitempty"`
	DataClasses  []string `json:"DataClasses,omitempty"`
	IsVerified   bool     `json:"IsVerified,omitempty"`
	IsFabricated bool     `json:"IsFabricated,omitempty"`
	IsSensitive  bool     `json:"IsSensitive,omitempty"`
	IsRetired    bool     `json:"IsRetired,omitempty"`
	IsSpamList   bool     `json:"IsSpamList,omitempty"`
}
