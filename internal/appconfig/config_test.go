package appconfig

import "testing"

func TestValidateOutput(t *testing.T) {
	if err := validate(Config{Output: "json"}); err != nil {
		t.Fatal(err)
	}
	if err := validate(Config{Output: "weird"}); err == nil {
		t.Fatal("expected invalid output error")
	}
}
