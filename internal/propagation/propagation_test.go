package propagation

import "testing"

func TestMajorityValues(t *testing.T) {
	results := []ResolverResult{
		{Resolver: "a", Values: []string{"1.1.1.1"}},
		{Resolver: "b", Values: []string{"1.1.1.1"}},
		{Resolver: "c", Values: []string{"2.2.2.2"}},
		{Resolver: "d", Error: "timeout"},
	}
	got, ok := majorityValues(results)
	if !ok {
		t.Fatal("majorityValues() should report a real majority")
	}
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("majorityValues() = %v, want [1.1.1.1]", got)
	}
}

func TestMajorityValuesTie(t *testing.T) {
	results := []ResolverResult{
		{Resolver: "a", Values: []string{"1.1.1.1"}},
		{Resolver: "b", Values: []string{"1.1.1.1"}},
		{Resolver: "c", Values: []string{"2.2.2.2"}},
		{Resolver: "d", Values: []string{"2.2.2.2"}},
	}
	got, ok := majorityValues(results)
	if ok {
		t.Fatalf("majorityValues() tie reported majority: %v", got)
	}
}
