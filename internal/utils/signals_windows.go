//go:build windows
// +build windows

package utils

import (
	"syscall"
)

// GetSignalByName returns the syscall.Signal for a given signal name (Windows)
func GetSignalByName(name string) syscall.Signal {
	switch name {
	case "SIGINT":
		return syscall.SIGINT
	case "SIGTERM":
		return syscall.SIGTERM
	case "SIGHUP":
		return syscall.SIGHUP
	default:
		return syscall.Signal(0) // Most Unix signals not available on Windows
	}
}

// IsValidSignal checks if the signal is valid (not zero)
func IsValidSignal(sig syscall.Signal) bool {
	return sig != 0
}
