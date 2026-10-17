//go:build !linux && !darwin && !windows

package session

import "os"

// applyTerminalModes 在非 Linux Unix 上保留系统默认模式；terminal 为 PTY，encoded 为 SSH 模式。
func applyTerminalModes(terminal *os.File, encoded string) error { return nil }
