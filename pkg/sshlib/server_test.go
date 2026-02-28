package sshlib_test

import (
	"context"
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
		Shell:       "/bin/sh",
	}

	srv, err := sshlib.NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	done := make(chan bool)
	go func() {
		if err := srv.Start(context.Background()); err != nil {
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
		name        string
		config      *sshlib.Config
		expectError bool
	}{
		{
			name: "valid config with password auth",
			config: &sshlib.Config{
				ListenAddr: "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				Password:   "test",
				Shell:      "/bin/sh",
			},
			expectError: false,
		},
		{
			name: "valid config with no auth",
			config: &sshlib.Config{
				ListenAddr: "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				Shell:       "/bin/sh",
			},
			expectError: false,
		},
		{
			name: "invalid shell path",
			config: &sshlib.Config{
				ListenAddr: "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				Shell:       "/this/path/does/not/exist",
			},
			expectError: true,
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

// TestHasPasswordAuth tests HasPasswordAuth method
func TestHasPasswordAuth(t *testing.T) {
	tests := []struct {
		name     string
		config   *sshlib.Config
		expected bool
	}{
		{
			name:     "with password",
			config:   &sshlib.Config{Password: "secret"},
			expected: true,
		},
		{
			name:     "without password",
			config:   &sshlib.Config{Password: ""},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.HasPasswordAuth()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestHasPublicKeyAuth tests HasPublicKeyAuth method
func TestHasPublicKeyAuth(t *testing.T) {
	tests := []struct {
		name     string
		config   *sshlib.Config
		expected bool
	}{
		{
			name:     "with authorized keys files",
			config:   &sshlib.Config{AuthorizedKeysFiles: "/home/user/.ssh/authorized_keys"},
			expected: true,
		},
		{
			name:     "with authorized keys content",
			config:   &sshlib.Config{AuthorizedKeys: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"},
			expected: true,
		},
		{
			name:     "without public key auth",
			config:   &sshlib.Config{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.HasPublicKeyAuth()
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
		Shell:       "/bin/sh",
	}

	srv, err := sshlib.NewServer(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	done := make(chan bool)
	go func() {
		if err := srv.Start(context.Background()); err != nil {
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
			name: "invalid shell path",
			config: &sshlib.Config{
				ListenAddr:  "127.0.0.1:2222",
				HostKeyPath: "/tmp/key",
				Shell:       "/this/path/does/not/exist",
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