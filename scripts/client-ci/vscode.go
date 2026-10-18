package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// vscode 启动 executable 的真实 Electron Remote SSH 窗口，验证扩展提供的远程编辑与终端结果。
func (f *fixture) vscode(ctx context.Context, executable string) error {
	if executable == "" {
		return fmt.Errorf("必须指定 -code")
	}
	code, err := filepath.Abs(executable)
	if err != nil {
		return err
	}
	workspace := filepath.Join(f.root, "remote-workspace")
	profile := filepath.Join(f.root, "code-user")
	extensions := filepath.Join(f.root, "extensions")
	if err = os.MkdirAll(workspace, 0700); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(profile, "User"), 0700); err != nil {
		return err
	}
	settings := map[string]any{"security.workspace.trust.enabled": false, "telemetry.telemetryLevel": "off", "workbench.startupEditor": "none", "extensions.autoUpdate": false, "update.mode": "none", "remote.SSH.configFile": f.config, "remote.SSH.useLocalServer": false, "remote.SSH.useExecServer": false, "remote.SSH.remotePlatform": map[string]string{"sshdev-ci": "linux"}, "remote.SSH.serverInstallPath": map[string]string{"sshdev-ci": filepath.Join(f.root, "remote-server")}, "remote.SSH.showLoginTerminal": false}
	settingsBytes, _ := json.Marshal(settings)
	if err = os.WriteFile(filepath.Join(profile, "User", "settings.json"), settingsBytes, 0600); err != nil {
		return err
	}
	base := []string{"--user-data-dir", profile, "--extensions-dir", extensions, "--disable-workspace-trust", "--no-sandbox", "--disable-gpu"}
	if _, err = f.execute(ctx, code, append(append([]string{}, base...), "--install-extension", "ms-vscode-remote.remote-ssh@0.120.0", "--force")...); err != nil {
		return err
	}
	fixturePath, err := filepath.Abs("scripts/vscode-fixture")
	if err != nil {
		return err
	}
	result := filepath.Join(f.root, "result.json")
	os.Remove(result)
	addr, err := freeAddress()
	if err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(addr)
	session := "sshdev-vscode-" + strconv.Itoa(os.Getpid())
	args := append(append([]string{}, base...), "--new-window", "--wait", "--verbose", "--remote-debugging-port="+port, "--extensionDevelopmentPath="+fixturePath, "--remote", "ssh-remote+sshdev-ci", workspace)
	log, err := os.Create(filepath.Join(f.root, "vscode.log"))
	if err != nil {
		return err
	}
	defer log.Close()
	command := exec.CommandContext(ctx, code, args...)
	command.Env = append(os.Environ(), "SSHDEV_E2E_RESULT="+result)
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() {
		exec.Command("agent-browser", "--session", session, "--cdp", port, "close").Run()
		command.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		killOwnedCode(f.root)
	}()
	defer func() {
		capture, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		f.execute(capture, "agent-browser", "--session", session, "--cdp", port, "screenshot", filepath.Join(f.root, "window.png"))
	}()
	for deadline := time.Now().Add(4 * time.Minute); time.Now().Before(deadline); {
		data, e := os.ReadFile(result)
		if e == nil {
			var proof struct {
				OK             bool   `json:"ok"`
				Error          string `json:"error"`
				RemoteName     string `json:"remoteName"`
				URI            string `json:"uri"`
				EditorText     string `json:"editorText"`
				TerminalMarker string `json:"terminalMarker"`
			}
			if e = json.Unmarshal(data, &proof); e != nil {
				return e
			}
			remoteURI, uriErr := url.Parse(proof.URI)
			if !proof.OK || proof.RemoteName != "ssh-remote" || uriErr != nil || remoteURI.Scheme != "vscode-remote" || remoteURI.Host != "ssh-remote+sshdev-ci" || proof.EditorText != "EDITOR_AFTER" || proof.TerminalMarker != "SSHDEV_TERMINAL_OK" {
				return fmt.Errorf("VS Code 真实客户端验收失败: %s", data)
			}
			return nil
		}
		select {
		case e := <-done:
			done = nil
			if e != nil {
				return fmt.Errorf("VS Code 启动器失败: %v", e)
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("VS Code Remote SSH 验收超时，查看 vscode.log 与 code-user/logs")
}

// killOwnedCode 在 Linux CI 中只终止命令行包含本次专属目录 root 的编辑器/服务进程。
func killOwnedCode(root string) {
	entries, _ := os.ReadDir("/proc")
	self := os.Getpid()
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == self {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err == nil && strings.Contains(string(data), root) {
			if process, e := os.FindProcess(pid); e == nil {
				process.Kill()
			}
		}
	}
}
