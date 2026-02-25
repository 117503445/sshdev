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

// TestSSHServerBasic tests basic SSH server functionality
func TestSSHServerBasic(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_host_key"
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

	// Configure server with no authentication (easiest for testing)
	config := &types.Config{
		ListenAddr:     fmt.Sprintf("127.0.0.1:%d", port),
		HostKeyPath:    hostKeyPath,
		AuthMode:       types.AuthModeNone,
		Username:       "",
		Password:       "",
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

	// Test SSH connection
	client, err := connectSSH("127.0.0.1", port, "", "")
	if err != nil {
		t.Fatalf("Failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	// Test a simple command
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	output, err := session.Output("echo 'hello world'")
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	expected := "hello world\n" // Commands output includes newline
	actual := string(output)
	if actual != expected {
		t.Errorf("Expected %q, got %q", expected, actual)
	}
}

// Helper function to generate a test host key
func generateTestHostKey(path string) error {
	// For testing, we can let the server generate the key
	// Just create an empty file that will be overwritten by the server
	return os.WriteFile(path, []byte{}, 0600)
}

// Helper function to connect to SSH server
func connectSSH(host string, port int, username, password string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Use no authentication when connecting to no-auth server
	if username == "" {
		config.Auth = []ssh.AuthMethod{}
	} else {
		config.Auth = []ssh.AuthMethod{
			ssh.Password(password),
		}
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