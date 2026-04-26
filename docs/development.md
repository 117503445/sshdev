# 开发注意事项

## 构建工具

项目使用 **Task (Taskfile)** 作为构建工具，**不是 Make**。

```bash
# 安装 Task
go install github.com/go-task/task/v3/cmd/task@latest

# 查看所有任务
task --list
```

## 日志

- 使用 [zerolog](https://github.com/rs/zerolog) 日志库
- 默认日志级别为 **Debug**
- 结构化 JSON 格式输出

## 代码风格

- 遵循 Go 标准代码风格
- 使用 `go fmt` 格式化
- 使用 `go vet` 检查

## 认证模式

- `password`: 用户名/密码认证
- `none`: 无认证（仅限测试环境）

## 端口转发

支持本地端口转发 (`-L`) 和远程端口转发 (`-R`)。

## GitHub Actions root 隧道

`.github/workflows/gh-root-pinggy.yml` 只在 `gh` 分支 push 或手动触发时运行。该 workflow 会在 CI 中进入 root 上下文，下载最新 release 的 `sshdev-linux-amd64`，使用公钥认证启动 `sshdev --pinggy`，并执行一次本地 SSH 自检。

日志中出现 `SSHDEV_CI_ROOT_LOGIN_OK user=root uid=0` 表示 sshdev 进程确实以 root 身份提供 shell。默认只加入临时自检公钥；如果需要在 Pinggy 保活窗口内外部登录，需要配置仓库 secret `SSHDEV_CI_AUTHORIZED_KEYS` 为允许登录的 SSH 公钥内容。
