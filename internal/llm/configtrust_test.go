// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 alibaba/open-code-review Contributors

package llm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigFileTrusted(t *testing.T) {
	dir := t.TempDir()

	// A 0600 config (owner-only) is trusted.
	secure := filepath.Join(dir, "secure.json")
	if err := os.WriteFile(secure, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configFileTrusted(secure); err != nil {
		t.Errorf("0600 config should be permitted, got %v", err)
	}

	// A missing file surfaces the stat error rather than silently passing.
	if err := configFileTrusted(filepath.Join(dir, "does-not-exist.json")); err == nil {
		t.Error("missing config should return an error")
	}

	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}

	// Chmod after creation: WriteFile's mode is subject to umask, but a group- or
	// world-writable config is exactly what must be rejected, so set it exactly.
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"group-writable", 0o660},
		{"world-writable", 0o606},
	} {
		p := filepath.Join(dir, tc.name+".json")
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := configFileTrusted(p); err == nil {
			t.Errorf("%s config (%o) should be rejected", tc.name, tc.mode)
		}
	}
}
