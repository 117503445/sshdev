package main

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/117503445/dev-sshd/internal/server"
	"github.com/117503445/dev-sshd/internal/types"
)

// TestSSHServerExecCommand tests executing commands via SSH
func TestSSHServerExecCommand(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_host_key_exec"
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

	// Configure server with no authentication for easier testing
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

	// Test various commands
	commands := []string{
		"echo hello",
		"printf 'test'",
		"sh -c 'echo exit_code=$?'",
	}

	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatalf("Failed to create session: %v", err)
			}
			defer session.Close()

			output, err := session.Output(cmd)
			if err != nil {
				t.Fatalf("Command '%s' failed: %v", cmd, err)
			}

			actual := string(output)
			// Verify we get some output
			if len(actual) == 0 {
				t.Errorf("Command '%s' returned empty output", cmd)
			}
			// Check specific outputs
			if cmd == "echo hello" && actual != "hello\n" {
				t.Errorf("Command '%s' expected 'hello\\n', got '%s'", cmd, actual)
			}
			if cmd == "printf 'test'" && actual != "test" {
				t.Errorf("Command '%s' expected 'test', got '%s'", cmd, actual)
			}
		})
	}
}

// TestSSHServerConcurrentConnections tests multiple concurrent connections
func TestSSHServerConcurrentConnections(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_host_key_concurrent"
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

	// Configure server with no authentication
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

	// Connect multiple clients concurrently
	numClients := 3
	results := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func(id int) {
			client, err := connectSSH("127.0.0.1", port, "", "")
			if err != nil {
				results <- fmt.Errorf("client %d failed to connect: %v", id, err)
				return
			}
			defer client.Close()

			// Execute a command on each client
			session, err := client.NewSession()
			if err != nil {
				results <- fmt.Errorf("client %d failed to create session: %v", id, err)
				return
			}
			defer session.Close()

			output, err := session.Output(fmt.Sprintf("echo 'client%d'", id))
			if err != nil {
				results <- fmt.Errorf("client %d command failed: %v", id, err)
				return
			}

			expected := fmt.Sprintf("client%d\n", id)
			actual := string(output)
			if actual != expected {
				results <- fmt.Errorf("client %d: expected %q, got %q", id, expected, actual)
				return
			}

			results <- nil
		}(i)
	}

	// Collect results from all clients
	for i := 0; i < numClients; i++ {
		err := <-results
		if err != nil {
			t.Error(err)
		}
	}
}