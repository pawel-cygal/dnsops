package dnssec

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		report Report
		want   string
	}{
		{"unsigned", Report{}, "unsigned"},
		{"signed", Report{ChildDNSKEYCount: 2, ChildRRSIGCount: 1, ParentDSCount: 1}, "signed"},
		{"broken-missing-dnskey", Report{ParentDSCount: 1}, "broken"},
		{"broken-missing-ds", Report{ChildDNSKEYCount: 1}, "broken"},
		{"broken-missing-rrsig", Report{ChildDNSKEYCount: 1, ParentDSCount: 1}, "broken"},
	}
	for _, tc := range cases {
		got, _ := classify(tc.report)
		if got != tc.want {
			t.Fatalf("%s: classify() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParentZone(t *testing.T) {
	got, err := parentZone("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "com" {
		t.Fatalf("parentZone(example.com) = %q", got)
	}
	if _, err := parentZone("com"); err == nil {
		t.Fatal("single-label domain should fail")
	}
}
