package utils

import (
	"syscall"
	"testing"
)

func TestGetSignalByName(t *testing.T) {
	tests := []struct {
		name     string
		signal   string
		expected syscall.Signal
	}{
		{
			name:     "SIGINT",
			signal:   "SIGINT",
			expected: syscall.SIGINT,
		},
		{
			name:     "SIGTERM",
			signal:   "SIGTERM",
			expected: syscall.SIGTERM,
		},
		{
			name:     "SIGHUP",
			signal:   "SIGHUP",
			expected: syscall.SIGHUP,
		},
		{
			name:     "unknown signal",
			signal:   "SIGUNKNOWN",
			expected: syscall.Signal(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetSignalByName(tt.signal)
			if result != tt.expected {
				t.Errorf("GetSignalByName(%s) = %v, expected %v", tt.signal, result, tt.expected)
			}
		})
	}
}

func TestIsValidSignal(t *testing.T) {
	tests := []struct {
		name     string
		signal   syscall.Signal
		expected bool
	}{
		{
			name:     "valid SIGINT",
			signal:   syscall.SIGINT,
			expected: true,
		},
		{
			name:     "valid SIGTERM",
			signal:   syscall.SIGTERM,
			expected: true,
		},
		{
			name:     "valid SIGKILL",
			signal:   syscall.SIGKILL,
			expected: true,
		},
		{
			name:     "invalid signal 0",
			signal:   0,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidSignal(tt.signal)
			if result != tt.expected {
				t.Errorf("IsValidSignal(%v) = %v, expected %v", tt.signal, result, tt.expected)
			}
		})
	}
}