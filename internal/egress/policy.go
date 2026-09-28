// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 alibaba/open-code-review Contributors

// Package egress enforces where review data and credentials may be sent.
package egress

import (
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
)

const (
	// EnvAllowedEndpoints, when set, restricts every outbound endpoint host to
	// this comma-separated allowlist. Unset means no host restriction.
	EnvAllowedEndpoints = "OCR_ALLOWED_ENDPOINTS"
	// EnvAllowInsecure lets plaintext http:// reach a non-loopback host.
	EnvAllowInsecure = "OCR_ALLOW_INSECURE_ENDPOINTS"
)

// CheckEndpoint rejects an outbound URL that violates the egress policy:
// plaintext http:// to a remote host, or a host outside the allowlist when one
// is configured. An empty URL is allowed only when no host allowlist is active.
func CheckEndpoint(rawURL string) error {
	if strings.TrimSpace(rawURL) == "" {
		if strings.TrimSpace(os.Getenv(EnvAllowedEndpoints)) != "" {
			return fmt.Errorf("cannot enforce %s for an endpoint resolved by an ambient transport", EnvAllowedEndpoints)
		}
		return nil
	}
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL %q: %w", rawURL, err)
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("endpoint URL %q must use http or https", rawURL)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("endpoint URL %q must include a host", rawURL)
	}
	if u.User != nil {
		return fmt.Errorf("endpoint URL %q must not include userinfo", rawURL)
	}
	if strings.EqualFold(u.Scheme, "http") && !isLoopback(host) && os.Getenv(EnvAllowInsecure) != "1" {
		return fmt.Errorf("refusing plaintext http:// endpoint %q (host %q); "+
			"use https:// or set %s=1", rawURL, host, EnvAllowInsecure)
	}
	if raw := strings.TrimSpace(os.Getenv(EnvAllowedEndpoints)); raw != "" && !hostAllowed(host, raw) {
		return fmt.Errorf("endpoint host %q is not in %s", host, EnvAllowedEndpoints)
	}
	return nil
}

// CheckRedirect allows redirects only within the configured endpoint origin.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if err := CheckEndpoint(req.URL.String()); err != nil {
		return err
	}
	if len(via) > 0 && !SameOrigin(via[0].URL, req.URL) {
		return fmt.Errorf("refusing cross-origin redirect from %q to %q", via[0].URL, req.URL)
	}
	return nil
}

// SameOrigin reports whether two HTTP URLs have the same scheme, host and port.
func SameOrigin(a, b *neturl.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	return strings.EqualFold(canonicalHostPort(a), canonicalHostPort(b))
}

func canonicalHostPort(u *neturl.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hostAllowed(host, allowlist string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, entry := range strings.Split(allowlist, ",") {
		if e := strings.ToLower(strings.TrimSpace(entry)); e != "" && e == host {
			return true
		}
	}
	return false
}
