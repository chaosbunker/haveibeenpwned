package pwned

import (
	"testing"
)

func TestBreach(t *testing.T) {
	t.Log(GetBreach("test@example.com", "breachedaccount/", "", "false", "false"))
	t.Log(GetBreach("test@example.com", "breachedaccount/", "adobe.com", "true", "false"))
	t.Log(GetBreach("", "breach/", "Adobe"))
	t.Log(GetBreach("test@example.com", "breachedaccount/", ""))
}

func TestPasteAccount(t *testing.T) {
	t.Log(GetPasteAccount("test@example.com", "pasteaccount/", ""))
}

func TestDataClasses(t *testing.T) {
	t.Log(GetDataClasses("", "dataclasses/", ""))
}

func TestPasswordCompromised(t *testing.T) {
	t.Log(IsPasswordCompromised("hello"))
}
