package sshlib

// Config holds the server configuration
type Config struct {
	ListenAddr           string
	HostKeyPath          string // Path to host key file (command line arg)
	HostKeyContent       string // Host key content (from env SSHDEV_HOST_KEY)
	Password             string // Password for authentication (from env SSHDEV_PASSWORD)
	AuthorizedKeysFiles  string // Authorized keys file paths, colon-separated (from env SSHDEV_AUTHORIZED_KEYS_FILES)
	AuthorizedKeys       string // Authorized keys content, newline-separated (from env SSHDEV_AUTHORIZED_KEYS)
	Shell                string // Shell to use (from env SSHDEV_SHELL, empty = current user's default)
	DisablePortForward   bool   // Disable local port forwarding (direct-tcpip), default: enabled
	DisableRemoteForward bool   // Disable remote port forwarding (tcpip-forward), default: enabled
}

// HasPasswordAuth returns true if password authentication is enabled
func (c *Config) HasPasswordAuth() bool {
	return c.Password != ""
}

// HasPublicKeyAuth returns true if public key authentication is enabled
func (c *Config) HasPublicKeyAuth() bool {
	return c.AuthorizedKeysFiles != "" || c.AuthorizedKeys != ""
}