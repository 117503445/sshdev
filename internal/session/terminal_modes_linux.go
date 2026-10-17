//go:build linux

package session

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// applyTerminalModes 将 encoded 中常用 SSH 终端模式应用到 terminal。
func applyTerminalModes(terminal *os.File, encoded string) error {
	modes, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		return err
	}
	for b := []byte(encoded); len(b) > 0; {
		op := b[0]
		b = b[1:]
		if op == 0 || op >= 160 {
			break
		}
		if len(b) < 4 {
			return fmt.Errorf("终端模式数据不完整")
		}
		value := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		var target *uint32
		var flag uint32
		switch op {
		case ssh.ECHO:
			target = &modes.Lflag
			flag = unix.ECHO
		case ssh.ICANON:
			target = &modes.Lflag
			flag = unix.ICANON
		case ssh.ISIG:
			target = &modes.Lflag
			flag = unix.ISIG
		case ssh.ICRNL:
			target = &modes.Iflag
			flag = unix.ICRNL
		case ssh.OPOST:
			target = &modes.Oflag
			flag = unix.OPOST
		case ssh.ONLCR:
			target = &modes.Oflag
			flag = unix.ONLCR
		}
		if target != nil {
			if value == 0 {
				*target &^= flag
			} else {
				*target |= flag
			}
		}
	}
	return unix.IoctlSetTermios(int(terminal.Fd()), unix.TCSETS, modes)
}
