package main

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/117503445/sshdev/internal/server"
	"github.com/117503445/sshdev/internal/types"
	"golang.org/x/crypto/ssh"
)

// TestSSHServerPasswordAuth tests SSH server with password authentication
func TestSSHServerPasswordAuth(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_host_key_pwd"
	err := generateTestHostKey(hostKeyPath)
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}
	defer os.Remove(hostKeyPath)

	// Find a free port to use
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Configure server with password authentication
	username := "testuser"
	password := "testpass"

	config := &types.Config{
		ListenAddr:     fmt.Sprintf("127.0.0.1:%d", port),
		HostKeyPath:    hostKeyPath,
		AuthMode:       types.AuthModePassword,
		Username:       username,
		Password:       password,
		AuthorizedKeys: "",
		Shell:          "/bin/sh",
	}

	// Create and start server in a goroutine
	srv, err := server.NewServer(config)
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

	// Give server a moment to start
	time.Sleep(500 * time.Millisecond)

	// Defer server cleanup
	defer func() {
		srv.Stop()
		<-done // Wait for server to stop
	}()

	// Test SSH connection with correct credentials
	client, err := connectSSHWithPassword("127.0.0.1", port, username, password)
	if err != nil {
		t.Fatalf("Failed to connect to SSH server with correct credentials: %v", err)
	}
	defer client.Close()

	// Test a simple command
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo 'authenticated'")
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	expected := "authenticated\n"
	actual := string(output)
	if actual != expected {
		t.Errorf("Expected %q, got %q", expected, actual)
	}

	// Test connection with incorrect credentials should fail
	_, err = connectSSHWithPassword("127.0.0.1", port, username, "wrongpass")
	if err == nil {
		t.Error("Expected authentication failure with wrong password, but got success")
	}
}

// TestSSHServerValidation tests config validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name          string
		config        *types.Config
		expectError   bool
	}{
		{
			name: "valid password auth with credentials",
			config: &types.Config{
				ListenAddr:     "127.0.0.1:2222",
				HostKeyPath:    "/tmp/key",
				AuthMode:       types.AuthModePassword,
				Username:       "test",
				Password:       "test",
				Shell:          "/bin/sh",
			},
			expectError: false,
		},
		{
			name: "password auth without username",
			config: &types.Config{
				ListenAddr:     "127.0.0.1:2222",
				HostKeyPath:    "/tmp/key",
				AuthMode:       types.AuthModePassword,
				Username:       "",
				Password:       "test",
				Shell:          "/bin/sh",
			},
			expectError: true,
		},
		{
			name: "no auth mode",
			config: &types.Config{
				ListenAddr:     "127.0.0.1:2222",
				HostKeyPath:    "/tmp/key",
				AuthMode:       types.AuthModeNone,
				Username:       "",
				Password:       "",
				Shell:          "/bin/sh",
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

// Helper function to connect with password authentication
func connectSSHWithPassword(host string, port int, username, password string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout: 10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, fmt.Errorf("client connection failed: %w", err)
	}

	client := ssh.NewClient(c, chans, reqs)
	return client, nil
}