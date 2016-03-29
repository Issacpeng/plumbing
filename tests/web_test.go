package tests

import (
	"net/http"
	"testing"
)

func Test_IndexHandler(t *testing.T) {
	endpoint := "https://containerops.me"

	resp, err := http.Get(endpoint)
	defer resp.Body.Close()

	if err != nil {
		t.Errorf("Test \"/\" Error: %s .", err.Error())
	} else {
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Test \"/\" Error StatusCode: %d .", resp.StatusCode)
		} else {
			t.Log("Test \"/\" Successfully.")
		}
	}
}
