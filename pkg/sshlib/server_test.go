package sshlib_test

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/117503445/sshdev/pkg/sshlib"
	"golang.org/x/crypto/ssh"
)

// TestNewServer tests creating a new server via pkg API
func TestNewServer(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_pkg_host_key"
	defer os.Remove(hostKeyPath)

	// Find a free port to use
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := &sshlib.Config{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		HostKeyPath: hostKeyPath,
		AuthMode:    sshlib.AuthModeNone,
		Shell:       "/bin/sh",
	}

	srv, err := sshlib.NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	done := make(chan bool)
	go func() {
		if err := srv.Start(); err != nil {
			t.Errorf("Server failed to start: %v", err)
		}
		done <- true
	}()

	time.Sleep(500 * time.Millisecond)

	defer func() {
		srv.Stop()
		<-done
	}()

	// Test connection works
	config := &ssh.ClientConfig{
		User:            "",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	client := ssh.NewClient(c, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo 'pkg test'")
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	expected := "pkg test\n"
	actual := string(output)
	if actual != expected {
		t.Errorf("Expected %q, got %q", expected, actual)
	}
}

// TestConfigValidation tests config validation via pkg API
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        *sshlib.Config
		expectError   bool
	}{
		{
			name: "valid password auth with credentials",
			config: &sshlib.Config{
				ListenAddr:  "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				AuthMode:    sshlib.AuthModePassword,
				Username:    "test",
				Password:    "test",
				Shell:       "/bin/sh",
			},
			expectError: false,
		},
		{
			name: "password auth without username",
			config: &sshlib.Config{
				ListenAddr:  "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				AuthMode:    sshlib.AuthModePassword,
				Username:    "",
				Password:    "test",
				Shell:       "/bin/sh",
			},
			expectError: true,
		},
		{
			name: "no auth mode",
			config: &sshlib.Config{
				ListenAddr:  "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				AuthMode:    sshlib.AuthModeNone,
				Username:    "",
				Password:    "",
				Shell:       "/bin/sh",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError && err == nil {
				t.Errorf("Expected validation error, but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

// TestAuthModeString tests AuthMode String method
func TestAuthModeString(t *testing.T) {
	tests := []struct {
		mode     sshlib.AuthMode
		expected string
	}{
		{sshlib.AuthModePassword, "password"},
		{sshlib.AuthModePublicKey, "publickey"},
		{sshlib.AuthModeNone, "none"},
		{sshlib.AuthModeAll, "all"},
		{sshlib.AuthMode(-1), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.mode.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestParseAuthMode tests parsing auth mode strings
func TestParseAuthMode(t *testing.T) {
	tests := []struct {
		input    string
		expected sshlib.AuthMode
	}{
		{"password", sshlib.AuthModePassword},
		{"publickey", sshlib.AuthModePublicKey},
		{"public_key", sshlib.AuthModePublicKey},
		{"pubkey", sshlib.AuthModePublicKey},
		{"none", sshlib.AuthModeNone},
		{"all", sshlib.AuthModeAll},
		{"unknown", sshlib.AuthModePassword},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sshlib.ParseAuthMode(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestDefaultAuthorizedKeysPath tests getting default path
func TestDefaultAuthorizedKeysPath(t *testing.T) {
	path := sshlib.DefaultAuthorizedKeysPath()
	if path == "" {
		t.Error("Expected non-empty path")
	}
}

// TestShellExitDisconnect tests that the connection is closed immediately after exit command
func TestShellExitDisconnect(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_exit_host_key"
	defer os.Remove(hostKeyPath)

	// Find a free port to use
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := &sshlib.Config{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", port),
		HostKeyPath: hostKeyPath,
		AuthMode:    sshlib.AuthModeNone,
		Shell:       "/bin/sh",
	}

	srv, err := sshlib.NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	done := make(chan bool)
	go func() {
		if err := srv.Start(); err != nil {
			t.Errorf("Server failed to start: %v", err)
		}
		done <- true
	}()

	time.Sleep(500 * time.Millisecond)

	defer func() {
		srv.Stop()
		<-done
	}()

	// Connect and start an interactive shell session
	config := &ssh.ClientConfig{
		User:            "",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	client := ssh.NewClient(c, chans, reqs)

	// Create a session with PTY (simulating interactive shell)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Set up PTY
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		t.Fatalf("Failed to request PTY: %v", err)
	}

	// Start shell
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to get stdin: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to get stdout: %v", err)
	}

	if err := session.Shell(); err != nil {
		t.Fatalf("Failed to start shell: %v", err)
	}

	// Give shell time to start
	time.Sleep(100 * time.Millisecond)

	// Send exit command
	_, err = stdin.Write([]byte("exit\n"))
	if err != nil {
		t.Fatalf("Failed to write exit command: %v", err)
	}
	stdin.Close()

	// Wait for session to close - should happen quickly after exit
	// If connection doesn't close properly, this will timeout
	sessionClosed := make(chan error, 1)
	go func() {
		// Read until EOF (connection closed)
		buf := make([]byte, 1024)
		for {
			_, err := stdout.Read(buf)
			if err != nil {
				sessionClosed <- err
				return
			}
		}
	}()

	select {
	case <-sessionClosed:
		// Connection closed as expected
	case <-time.After(3 * time.Second):
		t.Fatalf("Timeout waiting for connection to close after exit command")
	}

	session.Close()
	client.Close()
}

// TestNewServerWithInvalidConfig tests creating server with invalid config
func TestNewServerWithInvalidConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *sshlib.Config
		expectError bool
	}{
		{
			name: "invalid config - password auth without username",
			config: &sshlib.Config{
				ListenAddr:  "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				AuthMode:    sshlib.AuthModePassword,
				Username:    "",
				Password:    "",
				Shell:       "/bin/sh",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sshlib.NewServer(tt.config)
			if tt.expectError && err == nil {
				t.Error("Expected error, but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}