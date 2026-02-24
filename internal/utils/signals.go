package utils

import "syscall"

// GetSignalByName returns the syscall.Signal for a given signal name
func GetSignalByName(name string) syscall.Signal {
	switch name {
	case "SIGINT":
		return syscall.SIGINT
	case "SIGTERM":
		return syscall.SIGTERM
	case "SIGKILL":
		return syscall.SIGKILL
	case "SIGHUP":
		return syscall.SIGHUP
	case "SIGQUIT":
		return syscall.SIGQUIT
	case "SIGUSR1":
		return syscall.SIGUSR1
	case "SIGUSR2":
		return syscall.SIGUSR2
	default:
		return syscall.Signal(0) // Invalid signal
	}
}

// IsValidSignal checks if the signal is valid (not zero)
func IsValidSignal(sig syscall.Signal) bool {
	return sig != 0
}