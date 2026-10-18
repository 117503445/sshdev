// client-ci 在独占目录运行真实客户端验收，不修改用户 SSH 或编辑器配置。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// main 根据参数运行指定客户端验收，并保留证据到 data/client-ci。
func main() {
	mode := flag.String("client", "openssh", "客户端：openssh、winscp、vscode")
	binary := flag.String("binary", "data/sshdev.exe", "待验收程序")
	code := flag.String("code", "", "固定版本 VS Code 的启动程序")
	winscp := flag.String("winscp", "", "WinSCP.com 路径")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	path, err := filepath.Abs(*binary)
	if err == nil {
		err = runClient(ctx, *mode, path, *code, *winscp)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runClient 为 mode 建立独立服务，并使用 binary、code 或 winscp 运行客户端。
func runClient(ctx context.Context, mode, binary, code, winscp string) error {
	fixture, err := newFixture(ctx, mode, binary)
	if err != nil {
		return err
	}
	defer fixture.close()
	switch mode {
	case "openssh":
		err = fixture.openSSH(ctx)
	case "winscp":
		err = fixture.winSCP(ctx, winscp)
	case "vscode":
		err = fixture.vscode(ctx, code)
	default:
		return fmt.Errorf("未知客户端 %q", mode)
	}
	if err == nil {
		fmt.Printf("SSHDEV_CLIENT_OK client=%s root=%s\n", mode, fixture.root)
	}
	return err
}
