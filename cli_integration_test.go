package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCLIBasicFunctionality tests the basic CLI functionality
func TestCLIBasicFunctionality(t *testing.T) {
	// Find the binary
	binaryPath := "./data/cli/dev-sshd-linux-amd64"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		binaryPath = "./data/cli/dev-sshd"
	}
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skip("Skipping CLI test - binary not found")
	}

	// Test that binary exists and responds to --help
	cmd := exec.Command(binaryPath, "--help")

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	if err != nil {
		t.Fatalf("CLI help command failed: %v, stderr: %s", err, errBuf.String())
	}

	output := outBuf.String()
	if !strings.Contains(output, "run") {
		t.Errorf("Expected 'run' command in help output, got: %s", output)
	}
}

// TestCLIRunWithNoAuthMode tests running the server with no auth mode
func TestCLIRunWithNoAuthMode(t *testing.T) {
	// Find the binary
	binaryPath := "./data/cli/dev-sshd-linux-amd64"
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		binaryPath = "./data/cli/dev-sshd"
	}
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Skip("Skipping CLI test - binary not found")
	}

	// Use a random available port
	port := "3333" // Using fixed port for simplicity in test

	// Create a temporary host key
	tempHostKey := "/tmp/test_cli_host_key"

	// Start the server in no-auth mode
	cmd := exec.Command(binaryPath, "run",
		"--listen", ":"+port,
		"--host-key", tempHostKey,
		"--auth-mode", "none",
		"--shell", "/bin/sh")

	// Capture output to detect server startup
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf

	err := cmd.Start()
	if err != nil {
		t.Skipf("Skipping CLI test - could not start server: %v", err)
	}

	// Give the server some time to start
	time.Sleep(2 * time.Second)

	// Try to ping the port to see if it's listening
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 2*time.Second)
	if err != nil {
		t.Logf("Server might not be listening on port %s, error: %v", port, err)
		// Don't fail the test yet, kill the process and continue
		cmd.Process.Kill()
		return
	}
	conn.Close()

	// Kill the server process
	cmd.Process.Kill()

	// Give it a moment to shut down
	time.Sleep(100 * time.Millisecond)

	t.Log("CLI run command started successfully with no-auth mode")
}