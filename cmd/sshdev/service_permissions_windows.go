package main

import (
	"fmt"
	"net"
	"os/exec"
)

// secureDirectory 为 dir 移除继承权限，仅允许 SYSTEM 和管理员访问。
func secureDirectory(dir string) error { return restrictACL(dir, true) }

// secureFile 为 path 移除继承权限，仅允许 SYSTEM 和管理员访问。
func secureFile(path string) error { return restrictACL(path, false) }

// restrictACL 为 path 设置本地化无关的 SID 权限；directory 表示目录继承。
func restrictACL(path string, directory bool) error {
	permission := "F"
	if directory {
		permission = "(OI)(CI)F"
	}
	output, err := exec.Command("icacls.exe", path, "/inheritance:r", "/grant:r", "*S-1-5-18:"+permission, "*S-1-5-32-544:"+permission).CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置配置权限失败: %w: %s", err, output)
	}
	return nil
}

// installFirewall 为 name 创建限定 executable 和 listen 端口的 Windows 入站规则。
func installFirewall(name, executable, listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return nil
	}
	output, err := exec.Command("netsh.exe", "advfirewall", "firewall", "add", "rule", "name=sshdev-"+name, "dir=in", "action=allow", "protocol=TCP", "localport="+port, "program="+executable, "enable=yes").CombinedOutput()
	if err != nil {
		return fmt.Errorf("创建服务防火墙规则失败: %w: %s", err, output)
	}
	return nil
}

// uninstallFirewall 删除 name 服务拥有的防火墙规则，未创建规则时保持成功。
func uninstallFirewall(name string) error {
	// PowerShell 的 SilentlyContinue 允许仅绑定回环地址的服务没有入站规则。
	script := "Get-NetFirewallRule -DisplayName 'sshdev-" + name + "' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop"
	output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("删除服务防火墙规则失败: %w: %s", err, output)
	}
	return nil
}
