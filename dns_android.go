//go:build android && !cgo
// +build android,!cgo

package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

func init() {
	// On Android, when not using cgo, we need to manually set up the default DNS resolver.
	// This resolver will attempt Cloudflare's DNS over both IPv4 and IPv6.

	var dialer net.Dialer
	dnsServers := []string{
		"[2606:4700:4700::1111]:53", // Cloudflare IPv6
		"[2606:4700:4700::1001]:53", // Cloudflare IPv6
		"1.1.1.1:53",                // Cloudflare IPv4
		"1.0.0.1:53",                // Cloudflare IPv4
	}

		net.DefaultResolver = &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "udp" {
				return nil, fmt.Errorf("unsupported network %q", network)
			}

			queryCtx := ctx
			var cancel context.CancelFunc
			if _, hasDeadline := ctx.Deadline(); !hasDeadline {
				queryCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
			}

			var lastErr error
			for _, ip := range dnsServers {
				if err := queryCtx.Err(); err != nil {
					return nil, err
				}

				conn, err := dialer.DialContext(queryCtx, "udp", ip)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}

			if lastErr != nil {
				return nil, lastErr
			}
			return nil, net.ErrClosed
		},
	}
}
