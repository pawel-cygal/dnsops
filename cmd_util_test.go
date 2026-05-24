package main

import (
	"reflect"
	"testing"
)

func TestNormalizeFlagArgs(t *testing.T) {
	valueFlags := map[string]bool{"--resolver": true, "--baseline": true, "--resolvers": true, "-f": true, "--warn-days": true}
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"example.com", "A", "--json"}, []string{"--json", "example.com", "A"}},
		{[]string{"example.com", "--resolver", "8.8.8.8:53", "TXT"}, []string{"--resolver", "8.8.8.8:53", "example.com", "TXT"}},
		{[]string{"example.com", "--resolver=8.8.8.8:53", "TXT"}, []string{"--resolver=8.8.8.8:53", "example.com", "TXT"}},
		{[]string{"example.com", "example.org", "--warn-days", "30"}, []string{"--warn-days", "30", "example.com", "example.org"}},
	}
	for _, c := range cases {
		got := normalizeFlagArgs(c.in, valueFlags)
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("normalizeFlagArgs(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
