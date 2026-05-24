package mailcheck

import "testing"

func TestCountSPFLookups(t *testing.T) {
	spf := "v=spf1 include:_spf.google.com include:mail.example.com a mx exists:%{i} redirect=_spf.example.com ~all"
	if got := countSPFLookups(spf); got != 6 {
		t.Fatalf("countSPFLookups() = %d, want 6", got)
	}
}

func TestMatchingTXT(t *testing.T) {
	values := []string{"v=spf1 include:_spf.example.com ~all", "google-site-verification=abc"}
	got := matchingTXT(values, "v=spf1")
	if len(got) != 1 || got[0] != values[0] {
		t.Fatalf("matchingTXT() = %v", got)
	}
}
