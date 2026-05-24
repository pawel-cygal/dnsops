package expiry

import (
	"testing"
	"time"
)

func TestExpirationDate(t *testing.T) {
	ts, ok := expirationDate([]rdapEvent{
		{Action: "registration", Date: "2024-01-01T00:00:00Z"},
		{Action: "expiration", Date: "2027-01-15T12:00:00Z"},
	})
	if !ok {
		t.Fatal("expected expiration event")
	}
	if want := "2027-01-15T12:00:00Z"; ts.Format(time.RFC3339) != want {
		t.Fatalf("got %s, want %s", ts.Format(time.RFC3339), want)
	}
}

func TestClassify(t *testing.T) {
	if got := classify(90, 60, 14); got != "ok" {
		t.Fatalf("90 days => %s", got)
	}
	if got := classify(30, 60, 14); got != "warn" {
		t.Fatalf("30 days => %s", got)
	}
	if got := classify(7, 60, 14); got != "critical" {
		t.Fatalf("7 days => %s", got)
	}
}

func TestRegistrarName(t *testing.T) {
	got := registrarName([]rdapEntity{{
		Roles: []string{"registrar"},
		VCardArray: []any{"vcard", []any{
			[]any{"fn", map[string]any{}, "text", "Namecheap"},
		}},
	}})
	if got != "Namecheap" {
		t.Fatalf("registrarName() = %q", got)
	}
}
