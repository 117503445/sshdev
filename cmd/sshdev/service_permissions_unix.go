//go:build !windows

package main

import "os"

// secureDirectory 将 dir 限制为当前管理员可读写。
func secureDirectory(dir string) error { return os.Chmod(dir, 0700) }

// secureFile 将 path 配置文件限制为当前管理员可读写。
func secureFile(path string) error { return os.Chmod(path, 0600) }

// installFirewall 在 Unix 保留系统现有防火墙策略；name、executable、listen 为服务信息。
func installFirewall(name, executable, listen string) error { return nil }

// uninstallFirewall 在 Unix 保留系统现有防火墙策略；name 为服务名。
func uninstallFirewall(name string) error { return nil }
