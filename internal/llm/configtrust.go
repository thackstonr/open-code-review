// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 alibaba/open-code-review Contributors

package llm

import (
	"github.com/alibaba/open-code-review/internal/configtrust"
)

// configFileTrusted reports whether path is safe to control endpoint selection
// or source a credential command from.
//
// POSIX-only: Windows expresses this through NTFS ACLs, not the mode bits
// os.Stat synthesizes, so there it is a no-op.
func configFileTrusted(path string) error {
	return configtrust.Check(path)
}
