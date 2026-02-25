# sshdev

A simple SSH server for development environments.

## Build

```bash
task build:bin
```

## Usage

### Password Authentication Mode
```bash
SSHD_USERNAME=vscode SSHD_PASSWORD=secret ./dev-sshd
```

### Public Key Authentication Mode
```bash
./dev-sshd --auth-mode=publickey --authorized-keys=~/.ssh/authorized_keys
```

### No Authentication Mode (Development Only)
```bash
./dev-sshd --auth-mode=none
```

### Connect
```bash
ssh -p 2222 user@host
```

## Configuration

| Environment Variable | Description |
|---------------------|-------------|
| SSHD_LISTEN         | Listen address (default: 0.0.0.0:2222) |
| SSHD_USERNAME       | Authentication username |
| SSHD_PASSWORD       | Authentication password |
| SSHD_AUTH_MODE      | Authentication mode (password/publickey/none) |
| SSHD_HOST_KEY       | Host key file path |
| SSHD_SHELL          | Default shell (default: /bin/bash) |