package authority

import (
	"reflect"
	"testing"
)

func TestZoneCandidates(t *testing.T) {
	got := zoneCandidates("app.eu.example.com.")
	want := []string{"app.eu.example.com", "eu.example.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("zoneCandidates() = %v, want %v", got, want)
	}
}

func TestMajorityValues(t *testing.T) {
	got := majorityValues([][]string{
		{"1.1.1.1"},
		{"2.2.2.2"},
		{"1.1.1.1"},
	})
	want := []string{"1.1.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("majorityValues() = %v, want %v", got, want)
	}
}

func TestAuthConsistent(t *testing.T) {
	if !authConsistent([][]string{{"1.1.1.1"}, {"1.1.1.1"}}, []string{"1.1.1.1"}) {
		t.Fatal("same authoritative answers should be consistent")
	}
	if authConsistent([][]string{{"1.1.1.1"}, {"2.2.2.2"}}, []string{"1.1.1.1"}) {
		t.Fatal("different authoritative answers should not be consistent")
	}
}
