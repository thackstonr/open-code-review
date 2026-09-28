// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 alibaba/open-code-review Contributors

package configtrust

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	secure := filepath.Join(dir, "secure.json")
	if err := os.WriteFile(secure, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Check(secure); err != nil {
		t.Fatalf("Check(secure) = %v", err)
	}
	if err := Check(dir); err == nil {
		t.Fatal("directory should not be trusted as a config file")
	}
	if err := Check(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing config should fail")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(secure, 0o622); err != nil {
			t.Fatal(err)
		}
		if err := Check(secure); err == nil {
			t.Fatal("config writable by another user should fail")
		}
	}
}
