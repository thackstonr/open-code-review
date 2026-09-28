// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 alibaba/open-code-review Contributors

package egress

import (
	"net/http"
	"net/url"
	"testing"
)

func TestCheckEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		allow   string // OCR_ALLOWED_ENDPOINTS
		insec   string // OCR_ALLOW_INSECURE_ENDPOINTS
		wantErr bool
	}{
		{"https allowed", "https://api.anthropic.com/v1/messages", "", "", false},
		{"empty url is ambient auth", "", "", "", false},
		{"ambient auth fails closed with allowlist", "", "api.anthropic.com", "", true},
		{"remote plaintext rejected", "http://api.evil.example/v1", "", "", true},
		{"loopback ip plaintext ok", "http://127.0.0.1:4000/v1", "", "", false},
		{"localhost plaintext ok", "http://localhost:4000/v1", "", "", false},
		{"remote plaintext allowed with opt-out", "http://gateway.internal/v1", "", "1", false},
		{"allowlist hit", "https://api.anthropic.com/v1/messages", "api.anthropic.com", "", false},
		{"allowlist miss", "https://api.openai.com/v1", "api.anthropic.com", "", true},
		{"allowlist hit among several", "https://api.openai.com/v1", "api.anthropic.com , api.openai.com", "", false},
		{"allowlist is case-insensitive", "https://API.Anthropic.com/v1", "api.anthropic.com", "", false},
		{"unparseable url rejected", "http://ho\x7fst/x", "", "", true},
		{"missing host rejected", "https:///v1", "", "", true},
		{"non-http scheme rejected", "ftp://example.com/x", "", "", true},
		{"userinfo rejected", "https://user:secret@example.com/x", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.allow != "" {
				t.Setenv(EnvAllowedEndpoints, c.allow)
			}
			if c.insec != "" {
				t.Setenv(EnvAllowInsecure, c.insec)
			}
			err := CheckEndpoint(c.url)
			if (err != nil) != c.wantErr {
				t.Errorf("CheckEndpoint(%q) error = %v, wantErr = %v", c.url, err, c.wantErr)
			}
		})
	}
}

func TestCheckRedirect(t *testing.T) {
	first, _ := http.NewRequest(http.MethodPost, "https://api.example.com/v1", nil)

	for _, tc := range []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"same origin", "https://api.example.com/v2", false},
		{"default port is same origin", "https://api.example.com:443/v2", false},
		{"different host", "https://collector.example.com/v2", true},
		{"scheme downgrade", "http://api.example.com/v2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, _ := http.NewRequest(http.MethodPost, tc.target, nil)
			err := CheckRedirect(target, []*http.Request{first})
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckRedirect() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestSameOriginIPv6(t *testing.T) {
	a, _ := url.Parse("http://[::1]/a")
	b, _ := url.Parse("http://[::1]:80/b")
	if !SameOrigin(a, b) {
		t.Fatal("equivalent IPv6 origins should match")
	}
}
