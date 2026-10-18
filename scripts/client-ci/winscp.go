package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
)

// winSCP 使用 executable 的真实脚本接口验收指纹固定、文件传输、目录及删除。
func (f *fixture) winSCP(ctx context.Context, executable string) error {
	if executable == "" {
		return fmt.Errorf("必须指定 -winscp")
	}
	payload := bytes.Repeat([]byte("WinSCP\x00中文"), 200000)
	source := filepath.Join(f.root, "上传 文件.bin")
	download := filepath.Join(f.root, "下载 文件.bin")
	if err := os.WriteFile(source, payload, 0600); err != nil {
		return err
	}
	remoteDir := remotePath(filepath.Join(f.root, "WinSCP 远端"))
	fingerprint := "ssh-ed25519 255 " + strings.TrimPrefix(ssh.FingerprintSHA256(f.signer.PublicKey()), "SHA256:")
	script := fmt.Sprintf("option batch abort\noption confirm off\nopen sftp://client-ci@%s/ -password=\"%%SSHDEV_TEST_PASSWORD%%\" -hostkey=\"%s\"\nmkdir \"%s\"\nput \"%s\" \"%s/文件.bin\"\nget \"%s/文件.bin\" \"%s\"\nmv \"%s/文件.bin\" \"%s/重命名.bin\"\nrm \"%s/重命名.bin\"\nrmdir \"%s\"\nexit\n", f.addr, fingerprint, remoteDir, source, remoteDir, remoteDir, download, remoteDir, remoteDir, remoteDir, remoteDir)
	path := filepath.Join(f.root, "winscp.script")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		return err
	}
	values, err := godotenv.Read(filepath.Join(f.root, ".env"))
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "/ini=nul", "/nointeractiveinput", "/script="+path, "/log="+filepath.Join(f.root, "winscp.log"))
	command.Env = append(os.Environ(), "SSHDEV_TEST_PASSWORD="+values["SSHDEV_TEST_PASSWORD"])
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("WinSCP 验收失败: %w: %s", err, output)
	}
	read, err := os.ReadFile(download)
	if err != nil {
		return err
	}
	if sha256.Sum256(read) != sha256.Sum256(payload) {
		return fmt.Errorf("WinSCP 下载哈希不符")
	}
	return nil
}
