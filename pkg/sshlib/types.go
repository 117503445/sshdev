package sshlib

// AuthMode represents the authentication mode
type AuthMode int

const (
	AuthModePassword AuthMode = iota
	AuthModePublicKey
	AuthModeNone
	AuthModeAll // Allow all configured auth methods
)

func (m AuthMode) String() string {
	switch m {
	case AuthModePassword:
		return "password"
	case AuthModePublicKey:
		return "publickey"
	case AuthModeNone:
		return "none"
	case AuthModeAll:
		return "all"
	default:
		return "unknown"
	}
}

// Config holds the server configuration
type Config struct {
	ListenAddr           string
	HostKeyPath          string
	AuthMode             AuthMode
	Username             string
	Password             string
	AuthorizedKeys       string
	Shell                string
	DisablePortForward   bool // Disable local port forwarding (direct-tcpip), default: enabled
	DisableRemoteForward bool // Disable remote port forwarding (tcpip-forward), default: enabled
}