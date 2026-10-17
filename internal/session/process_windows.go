package session

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/UserExistsError/conpty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

// shellArgs 根据 shell 类型及 isExec 为 command 选择原生参数。
func shellArgs(shell, command string, isExec bool) []string {
	name := strings.ToLower(filepath.Base(shell))
	if name == "powershell" || name == "powershell.exe" || name == "pwsh" || name == "pwsh.exe" {
		args := []string{"-NoLogo", "-NoProfile"}
		if isExec {
			return append(args, "-NonInteractive", "-Command", command)
		}
		return append(args, "-NoExit")
	}
	if name == "cmd" || name == "cmd.exe" {
		if isExec {
			return []string{"/d", "/s", "/c", command}
		}
		return []string{"/d"}
	}
	if isExec {
		return []string{"-c", command}
	}
	return nil
}

// prepareCommand 为 cmd 建立独立 Windows 进程组。
func prepareCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED, CmdLine: commandLine(cmd)}
}

// commandLine 为 cmd 构造原生命令行，保留 cmd.exe /c 内部的引号语义。
func commandLine(cmd *exec.Cmd) string {
	if strings.EqualFold(filepath.Base(cmd.Path), "cmd.exe") && len(cmd.Args) == 5 && cmd.Args[3] == "/c" {
		return syscall.EscapeArg(cmd.Path) + ` /d /s /c "` + cmd.Args[4] + `"`
	}
	args := make([]string, len(cmd.Args))
	for i, arg := range cmd.Args {
		args[i] = syscall.EscapeArg(arg)
	}
	return strings.Join(args, " ")
}

// manageProcess 将 pid 纳入退出即清理的 Job Object，返回进程树清理函数。
func manageProcess(pid int) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	defer windows.CloseHandle(handle)
	if err = windows.AssignProcessToJobObject(job, handle); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	return func() { windows.CloseHandle(job) }, nil
}

// signalProcess 将 name 指定的终止信号送到 pid；非终端会话不模拟 Ctrl+C。
func signalProcess(pid int, name string) error {
	name = strings.TrimPrefix(strings.ToUpper(name), "SIG")
	if name != "TERM" && name != "KILL" && name != "HUP" {
		return unsupportedSignal(name)
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.TerminateProcess(handle, 1)
}

// exitResult 将 err 转为 Windows 退出码，Windows 不返回 POSIX 退出信号。
func exitResult(err error) (uint32, string) {
	if err == nil {
		return 0, ""
	}
	var e *exec.ExitError
	if errors.As(err, &e) {
		return uint32(e.ExitCode()), ""
	}
	return 1, ""
}

// startTerminal 使用 ConPTY 运行 cmd，按 term 设置尺寸并连接 ch。
func startTerminal(ch ssh.Channel, cmd *exec.Cmd, term *terminalRequest) (*process, error) {
	terminal, err := conpty.Start(commandLine(cmd), conpty.ConPtyDimensions(int(term.Columns), int(term.Rows)), conpty.ConPtyEnv(cmd.Env))
	if err != nil {
		return nil, fmt.Errorf("创建 ConPTY 失败（需 Windows 10 1809 或更新版本）: %w", err)
	}
	kill, err := manageProcess(terminal.Pid())
	if err != nil {
		terminal.Close()
		return nil, err
	}
	drained := copyTerminal(ch, terminal)
	p := &process{done: make(chan struct{}), kill: kill}
	p.signal = func(name string) error {
		if strings.TrimPrefix(strings.ToUpper(name), "SIG") == "INT" {
			_, err := terminal.Write([]byte{3})
			return err
		}
		return signalProcess(terminal.Pid(), name)
	}
	p.resize = func(cols, rows uint32) error { return terminal.Resize(int(cols), int(rows)) }
	p.wait = func() (uint32, string) {
		code, err := terminal.Wait(context.Background())
		p.stop()
		p.mu.Lock()
		terminal.Close()
		p.mu.Unlock()
		drained()
		if err != nil {
			return 1, ""
		}
		return code, ""
	}
	return p, nil
}

// resumeCommand 在 pid 已加入 Job Object 后恢复其初始线程，避免子进程逃逸清理范围。
func resumeCommand(pid int) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != uint32(pid) {
			continue
		}
		thread, e := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if e != nil {
			return e
		}
		_, e = windows.ResumeThread(thread)
		windows.CloseHandle(thread)
		return e
	}
	return fmt.Errorf("找不到待恢复进程 %d 的初始线程", pid)
}
