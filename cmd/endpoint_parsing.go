package cmd

import (
	"fmt"
	"net"
	"strings"
)

// parseEndpointAddress extracts the host from an endpoint string while tolerating
// malformed values instead of panicking when slicing into them.
func parseEndpointAddress(endpoint string) (ipv4, ipv6 string, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", "", fmt.Errorf("empty endpoint")
	}

	if strings.HasPrefix(endpoint, "[") {
		end := strings.LastIndex(endpoint, "]")
		if end <= 0 {
			return "", "", fmt.Errorf("malformed IPv6 endpoint %q", endpoint)
		}

		host := endpoint[1:end]
		if host == "" {
			return "", "", fmt.Errorf("empty IPv6 host in endpoint %q", endpoint)
		}

		if end+1 < len(endpoint) {
			if endpoint[end+1] != ':' {
				return "", "", fmt.Errorf("malformed endpoint %q", endpoint)
			}
		}

		return "", host, nil
	}

	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		if strings.Count(endpoint, ":") == 0 {
			host = endpoint
		} else {
			return "", "", fmt.Errorf("malformed endpoint %q: %w", endpoint, err)
		}
	}

	if host == "" {
		return "", "", fmt.Errorf("empty host in endpoint %q", endpoint)
	}

	if strings.Contains(host, ":") {
		return "", host, nil
	}

	return host, "", nil
}
