// Package embedded contains embedded resources for sshdev
package embedded

import _ "embed"

// HostKey is the built-in ED25519 host key for sshdev
// This key is embedded at build time and can be used by setting SSHDEV_HOST_KEY_BUILTIN
//
//go:embed host_key
var HostKey string