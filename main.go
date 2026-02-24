package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Configure logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("")

	// Load configuration
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("[FATAL] Failed to load config: %v", err)
	}

	// Create server
	server, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("[FATAL] Failed to create server: %v", err)
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Printf("[INFO] Received shutdown signal")
		server.Stop()
		os.Exit(0)
	}()

	// Start server
	if err := server.Start(); err != nil {
		log.Fatalf("[FATAL] Server error: %v", err)
	}
}
