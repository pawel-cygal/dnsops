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

func TestResolversForProfiles(t *testing.T) {
	resolvers, err := ResolversForProfiles([]string{"eu", "us"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolvers) == 0 {
		t.Fatal("expected non-empty resolver list")
	}
	seen := map[string]bool{}
	for _, resolver := range resolvers {
		if seen[resolver] {
			t.Fatalf("duplicate resolver in merged profiles: %s", resolver)
		}
		seen[resolver] = true
	}
	if !seen["9.9.9.9:53"] || !seen["8.8.4.4:53"] {
		t.Fatalf("merged profiles missing expected resolvers: %v", resolvers)
	}
}

func TestResolversForProfilesGlobal(t *testing.T) {
	global, err := ResolversForProfiles([]string{"global"})
	if err != nil {
		t.Fatal(err)
	}
	euUS, err := ResolversForProfiles([]string{"default", "eu", "us", "asia", "oceania", "south-america"})
	if err != nil {
		t.Fatal(err)
	}
	if len(global) != len(euUS) {
		t.Fatalf("global resolver count = %d, want %d", len(global), len(euUS))
	}
}

func TestResolversForProfilesUnknown(t *testing.T) {
	if _, err := ResolversForProfiles([]string{"mars"}); err == nil {
		t.Fatal("expected unknown profile error")
	}
}
