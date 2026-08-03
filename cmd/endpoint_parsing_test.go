package cmd

import (
	"testing"
)

func TestParseEndpointAddressRejectsMalformedValues(t *testing.T) {
	_, _, err := parseEndpointAddress("")
	if err == nil {
		t.Fatal("expected malformed endpoint to be rejected")
	}

	_, _, err = parseEndpointAddress("[::1")
	if err == nil {
		t.Fatal("expected malformed IPv6 endpoint to be rejected")
	}
}

func TestParseEndpointAddressAcceptsIPv4AndIPv6(t *testing.T) {
	ipv4, ipv6, err := parseEndpointAddress("1.2.3.4:443")
	if err != nil {
		t.Fatalf("unexpected error for IPv4 endpoint: %v", err)
	}
	if ipv4 != "1.2.3.4" || ipv6 != "" {
		t.Fatalf("unexpected IPv4 parse result: got %q/%q", ipv4, ipv6)
	}

	ipv4, ipv6, err = parseEndpointAddress("[2001:db8::1]:443")
	if err != nil {
		t.Fatalf("unexpected error for IPv6 endpoint: %v", err)
	}
	if ipv4 != "" || ipv6 != "2001:db8::1" {
		t.Fatalf("unexpected IPv6 parse result: got %q/%q", ipv4, ipv6)
	}
}
