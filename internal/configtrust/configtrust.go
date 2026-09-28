// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 alibaba/open-code-review Contributors

// Package configtrust validates configuration before it controls egress or execution.
package configtrust

import (
	"fmt"
	"os"
	"runtime"
)

// Check rejects a non-regular config or one writable by another POSIX user.
func Check(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing untrusted config %s: not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("refusing untrusted config %s: writable by group or others; run 'chmod 600 %s'", path, path)
	}
	return nil
}
