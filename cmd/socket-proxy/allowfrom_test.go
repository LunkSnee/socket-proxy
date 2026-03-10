package main

import (
	"testing"

	"github.com/wollomatic/socket-proxy/internal/config"
)

func TestIsAllowedClient_CIDRStripsPrefix(t *testing.T) {
	// configure a single allow-from entry that includes an IPv6 prefix
	cfg = &config.Config{AllowFrom: []string{"fdd0:0:0:4::1/64"}}

	// the client address that should be permitted
	allowed := "fdd0:0:0:4::1"
	ok, err := isAllowedClient(allowed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected client %s to be allowed by CIDR entry", allowed)
	}
}

func TestIsAllowedClient_PlainAddressStillWorks(t *testing.T) {
	cfg = &config.Config{AllowFrom: []string{"127.0.0.1"}}
	ok, err := isAllowedClient("127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("plain IPv4 literal should be allowed")
	}
}

func TestIsAllowedClient_CIDRNetwork(t *testing.T) {
	cfg = &config.Config{AllowFrom: []string{"192.168.0.0/24"}}
	ok, err := isAllowedClient("192.168.0.42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("address inside network should be allowed")
	}
}

// ensure that a bad CIDR is still handled gracefully (no panic)
func TestIsAllowedClient_MalformedCIDR(t *testing.T) {
	cfg = &config.Config{AllowFrom: []string{"not-an-ip/123"}}
	// the call should not panic; it will simply treat the string as a hostname and
	// fail to look it up (which is fine).
	ok, err := isAllowedClient("10.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("malformed CIDR must not allow arbitrary clients")
	}
}
