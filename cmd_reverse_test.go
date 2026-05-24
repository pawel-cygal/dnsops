package main

import "testing"

func TestReverseNameIPv4(t *testing.T) {
	got, err := reverseName("192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.2.0.192.in-addr.arpa" {
		t.Fatalf("reverseName() = %q", got)
	}
}

func TestReverseNameInvalid(t *testing.T) {
	if _, err := reverseName("not-an-ip"); err == nil {
		t.Fatal("expected invalid IP error")
	}
}
