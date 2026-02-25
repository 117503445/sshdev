# sshdev

A simple SSH server for development environments. Can be used as a CLI tool or as a Go library.

## As a CLI Tool

### Build
```bash
task build:bin
# or
go build -o sshdev ./cmd/dev-sshd
```

### Usage

#### Password Authentication Mode
```bash
SSHD_USERNAME=vscode SSHD_PASSWORD=secret ./sshdev run
```

#### Public Key Authentication Mode
```bash
./sshdev run --auth-mode=publickey --authorized-keys=~/.ssh/authorized_keys
```

#### No Authentication Mode (Development Only)
```bash
./sshdev run --auth-mode=none
```

#### Connect
```bash
ssh -p 2222 user@host
```

### Configuration

| Environment Variable | Description |
|---------------------|-------------|
| SSHD_LISTEN         | Listen address (default: 0.0.0.0:2222) |
| SSHD_USERNAME       | Authentication username |
| SSHD_PASSWORD       | Authentication password |
| SSHD_AUTH_MODE      | Authentication mode (password/publickey/none/all) |
| SSHD_HOST_KEY       | Host key file path |
| SSHD_SHELL          | Default shell (default: /bin/bash) |
| SSHD_AUTHORIZED_KEYS | Authorized keys file path |

## As a Go Library

### Installation
```bash
go get github.com/117503445/sshdev/pkg/sshlib
```

### Usage Example

```go
package main

import (
    "github.com/117503445/sshdev/pkg/sshlib"
)

func main() {
    cfg := &sshlib.Config{
        ListenAddr:     "0.0.0.0:2222",
        HostKeyPath:    "./host_key",
        AuthMode:       sshlib.AuthModePassword,
        Username:       "user",
        Password:       "secret",
        Shell:          "/bin/bash",
    }

    server, err := sshlib.NewServer(cfg)
    if err != nil {
        panic(err)
    }

    if err := server.Start(); err != nil {
        panic(err)
    }

    // To stop the server:
    // server.Stop()
}
```

### Library API

#### Types
- `AuthMode`: Authentication mode (Password, PublicKey, None, All)
- `Config`: Server configuration
- `Server`: Server interface with Start() and Stop() methods

#### Functions
- `NewServer(cfg *Config) (Server, error)`: Creates a new SSH server
- `ParseAuthMode(s string) AuthMode`: Parses an auth mode string
- `DefaultAuthorizedKeysPath() string`: Returns default authorized_keys path
- `Config.Validate() error`: Validates the configuration

#### Errors
- `ErrInvalidConfig`: Returned when configuration is invalid
- `ErrAuthenticationFailed`: Returned when authentication fails