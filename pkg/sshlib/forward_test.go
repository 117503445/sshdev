package sshlib_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/117503445/sshdev/pkg/sshlib"
	"golang.org/x/crypto/ssh"
)

// findFreePort finds a free port to use
func findFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

// startEchoServer starts a simple echo server for testing
func startEchoServer(t *testing.T, port int) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	return listener, nil
}

// TestLocalPortForwarding tests local port forwarding (direct-tcpip)
func TestLocalPortForwarding(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_forward_host_key"
	defer os.Remove(hostKeyPath)

	// Find free ports
	sshPort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free SSH port: %v", err)
	}

	echoPort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free echo port: %v", err)
	}

	// Start echo server
	echoListener, err := startEchoServer(t, echoPort)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	// Configure and start SSH server with port forwarding enabled (default)
	cfg := &sshlib.Config{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", sshPort),
		HostKeyPath: hostKeyPath,
		AuthMode:    sshlib.AuthModeNone,
		Shell:       "/bin/sh",
		// DisablePortForward defaults to false (enabled)
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

	// Connect to SSH server
	sshConfig := &ssh.ClientConfig{
		User:            "",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshAddr := fmt.Sprintf("127.0.0.1:%d", sshPort)
	conn, err := net.DialTimeout("tcp", sshAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial SSH server: %v", err)
	}
	defer conn.Close()

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, sshAddr, sshConfig)
	if err != nil {
		t.Fatalf("Failed to create SSH client connection: %v", err)
	}
	defer clientConn.Close()

	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	// Test local port forwarding by dialing through the SSH connection
	echoAddr := fmt.Sprintf("127.0.0.1:%d", echoPort)
	forwardedConn, err := client.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("Failed to dial through SSH tunnel: %v", err)
	}
	defer forwardedConn.Close()

	// Send test data
	testData := "Hello, Port Forwarding!"
	_, err = forwardedConn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("Failed to write to forwarded connection: %v", err)
	}

	// Read response with timeout
	buf := make([]byte, len(testData))
	forwardedConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(forwardedConn, buf)
	if err != nil {
		t.Fatalf("Failed to read from forwarded connection: %v", err)
	}

	if string(buf) != testData {
		t.Errorf("Expected %q, got %q", testData, string(buf))
	}
}

// TestLocalPortForwardingDisabled tests that port forwarding can be disabled
func TestLocalPortForwardingDisabled(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_forward_disabled_host_key"
	defer os.Remove(hostKeyPath)

	// Find free ports
	sshPort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free SSH port: %v", err)
	}

	echoPort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free echo port: %v", err)
	}

	// Start echo server
	echoListener, err := startEchoServer(t, echoPort)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	// Configure and start SSH server with port forwarding DISABLED
	cfg := &sshlib.Config{
		ListenAddr:         fmt.Sprintf("127.0.0.1:%d", sshPort),
		HostKeyPath:        hostKeyPath,
		AuthMode:           sshlib.AuthModeNone,
		Shell:              "/bin/sh",
		DisablePortForward: true, // Disabled
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

	// Connect to SSH server
	sshConfig := &ssh.ClientConfig{
		User:            "",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshAddr := fmt.Sprintf("127.0.0.1:%d", sshPort)
	conn, err := net.DialTimeout("tcp", sshAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial SSH server: %v", err)
	}
	defer conn.Close()

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, sshAddr, sshConfig)
	if err != nil {
		t.Fatalf("Failed to create SSH client connection: %v", err)
	}
	defer clientConn.Close()

	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	// Try local port forwarding - should fail
	echoAddr := fmt.Sprintf("127.0.0.1:%d", echoPort)
	_, err = client.Dial("tcp", echoAddr)
	if err == nil {
		t.Error("Expected port forwarding to be rejected, but it succeeded")
	}
}

// TestRemotePortForwarding tests remote port forwarding (tcpip-forward)
func TestRemotePortForwarding(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_remote_forward_host_key"
	defer os.Remove(hostKeyPath)

	// Find free ports
	sshPort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free SSH port: %v", err)
	}

	remotePort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free remote port: %v", err)
	}

	// Configure and start SSH server with remote port forwarding enabled (default)
	cfg := &sshlib.Config{
		ListenAddr:  fmt.Sprintf("127.0.0.1:%d", sshPort),
		HostKeyPath: hostKeyPath,
		AuthMode:    sshlib.AuthModeNone,
		Shell:       "/bin/sh",
		// DisableRemoteForward defaults to false (enabled)
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

	// Connect to SSH server
	sshConfig := &ssh.ClientConfig{
		User:            "",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshAddr := fmt.Sprintf("127.0.0.1:%d", sshPort)
	conn, err := net.DialTimeout("tcp", sshAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial SSH server: %v", err)
	}
	defer conn.Close()

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, sshAddr, sshConfig)
	if err != nil {
		t.Fatalf("Failed to create SSH client connection: %v", err)
	}
	defer clientConn.Close()

	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	// Request remote port forwarding
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", remotePort)
	listener, err := client.Listen("tcp", remoteAddr)
	if err != nil {
		t.Fatalf("Failed to request remote port forwarding: %v", err)
	}
	defer listener.Close()

	// Handle forwarded connections
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		conn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept forwarded connection: %v", err)
			return
		}
		defer conn.Close()

		// Echo received data
		io.Copy(conn, conn)
	}()

	// Wait for listener to be ready
	time.Sleep(100 * time.Millisecond)

	// Connect to the remote forwarded port
	testConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		t.Fatalf("Failed to connect to remote forward port: %v", err)
	}
	defer testConn.Close()

	// Send test data
	testData := "Hello, Remote Forward!"
	_, err = testConn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("Failed to write to remote forward connection: %v", err)
	}

	// Read response with timeout
	buf := make([]byte, len(testData))
	testConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(testConn, buf)
	if err != nil {
		t.Fatalf("Failed to read from remote forward connection: %v", err)
	}

	if string(buf) != testData {
		t.Errorf("Expected %q, got %q", testData, string(buf))
	}
}

// TestRemotePortForwardingDisabled tests that remote port forwarding can be disabled
func TestRemotePortForwardingDisabled(t *testing.T) {
	// Create a temporary host key file
	hostKeyPath := "/tmp/test_remote_forward_disabled_host_key"
	defer os.Remove(hostKeyPath)

	// Find free ports
	sshPort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free SSH port: %v", err)
	}

	remotePort, err := findFreePort()
	if err != nil {
		t.Fatalf("Failed to find free remote port: %v", err)
	}

	// Configure and start SSH server with remote port forwarding DISABLED
	cfg := &sshlib.Config{
		ListenAddr:           fmt.Sprintf("127.0.0.1:%d", sshPort),
		HostKeyPath:          hostKeyPath,
		AuthMode:             sshlib.AuthModeNone,
		Shell:                "/bin/sh",
		DisableRemoteForward: true, // Disabled
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

	// Connect to SSH server
	sshConfig := &ssh.ClientConfig{
		User:            "",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshAddr := fmt.Sprintf("127.0.0.1:%d", sshPort)
	conn, err := net.DialTimeout("tcp", sshAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial SSH server: %v", err)
	}
	defer conn.Close()

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, sshAddr, sshConfig)
	if err != nil {
		t.Fatalf("Failed to create SSH client connection: %v", err)
	}
	defer clientConn.Close()

	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	// Try remote port forwarding - should fail
	remoteAddr := fmt.Sprintf("127.0.0.1:%d", remotePort)
	_, err = client.Listen("tcp", remoteAddr)
	if err == nil {
		t.Error("Expected remote port forwarding to be rejected, but it succeeded")
	}
}
