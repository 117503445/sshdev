package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// openSSH 使用真实 ssh/sftp/scp 验证命令、独立流、退出码、文件和 TCP 转发。
func (f *fixture) openSSH(ctx context.Context) error {
	command := "printf OPENSSH_OK; printf OPENSSH_ERR >&2; exit 17"
	if runtime.GOOS == "windows" {
		command = "[Console]::Out.Write('OPENSSH_OK'); [Console]::Error.Write('OPENSSH_ERR'); exit 17"
	}
	client := exec.CommandContext(ctx, "ssh", "-F", f.config, "sshdev-ci", command)
	var out, stderr bytes.Buffer
	client.Stdout = &out
	client.Stderr = &stderr
	err := client.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 17 || out.String() != "OPENSSH_OK" || stderr.String() != "OPENSSH_ERR" {
		return fmt.Errorf("OpenSSH 流或退出码错误: out=%q err=%q (%v)", out.String(), stderr.String(), err)
	}
	source := filepath.Join(f.root, "上传 文件.bin")
	download := filepath.Join(f.root, "下载 文件.bin")
	payload := bytes.Repeat([]byte("SFTP\x00\xff中文"), 150000)
	if err = os.WriteFile(source, payload, 0600); err != nil {
		return err
	}
	remoteDir := remotePath(filepath.Join(f.root, "远端 空格"))
	remote := remoteDir + "/文件.bin"
	batch := fmt.Sprintf("mkdir \"%s\"\nput \"%s\" \"%s\"\nget \"%s\" \"%s\"\nrename \"%s\" \"%s.new\"\nrm \"%s.new\"\nrmdir \"%s\"\n", remoteDir, filepath.ToSlash(source), remote, remote, filepath.ToSlash(download), remote, remote, remote, remoteDir)
	batchPath := filepath.Join(f.root, "sftp.batch")
	if err = os.WriteFile(batchPath, []byte(batch), 0600); err != nil {
		return err
	}
	if _, err = f.execute(ctx, "sftp", "-F", f.config, "-b", batchPath, "sshdev-ci"); err != nil {
		return err
	}
	read, err := os.ReadFile(download)
	if err != nil {
		return err
	}
	if sha256.Sum256(read) != sha256.Sum256(payload) {
		return fmt.Errorf("OpenSSH SFTP 哈希不符")
	}
	target := remotePath(filepath.Join(f.root, "scp 空格.bin"))
	if _, err = f.execute(ctx, "scp", "-F", f.config, source, "sshdev-ci:"+target); err != nil {
		return err
	}
	scpDownload := filepath.Join(f.root, "scp-down.bin")
	if _, err = f.execute(ctx, "scp", "-F", f.config, "sshdev-ci:"+target, scpDownload); err != nil {
		return err
	}
	read, err = os.ReadFile(scpDownload)
	if err != nil {
		return err
	}
	if sha256.Sum256(read) != sha256.Sum256(payload) {
		return fmt.Errorf("OpenSSH scp 哈希不符")
	}
	return f.forward(ctx)
}

// forward 验证真实 ssh -L 及 -R 双向转发。
func (f *fixture) forward(ctx context.Context) error {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer backend.Close()
	go func() {
		for {
			conn, e := backend.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	local, err := freeAddress()
	if err != nil {
		return err
	}
	remote, err := freeAddress()
	if err != nil {
		return err
	}
	forward := exec.CommandContext(ctx, "ssh", "-F", f.config, "-N", "-o", "ExitOnForwardFailure=yes", "-L", local+":"+backend.Addr().String(), "-R", remote+":"+backend.Addr().String(), "sshdev-ci")
	if err = forward.Start(); err != nil {
		return err
	}
	defer func() { forward.Process.Kill(); forward.Wait() }()
	for _, addr := range []string{local, remote} {
		ok := false
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
			conn, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if e == nil {
				conn.SetDeadline(time.Now().Add(time.Second))
				io.WriteString(conn, "FORWARD_OK")
				buf := make([]byte, len("FORWARD_OK"))
				_, e = io.ReadFull(conn, buf)
				conn.Close()
				if e == nil && strings.TrimSpace(string(buf)) == "FORWARD_OK" {
					ok = true
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ok {
			return fmt.Errorf("OpenSSH 转发失败: %s", addr)
		}
	}
	return nil
}
