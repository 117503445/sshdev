# 会话、文件传输与系统服务

## 会话行为

- shell 与 exec 支持退出码；非 PTY 会话将 stdout 和 stderr 分开传输，客户端不关闭 stdin 也能收到执行结果。
- 请求处理与进程等待并行。Unix PTY 和 Windows ConPTY 支持初始尺寸、窗口调整、交互输入及 Ctrl+C。
- Unix 支持 INT、TERM、KILL、HUP、QUIT、USR1、USR2 信号，并对独立进程组执行清理；Windows 终端 INT 转为 Ctrl+C，TERM/KILL/HUP 终止进程，非终端 Windows 会话不模拟 POSIX INT。
- Windows 非终端进程先挂起，加入 Job Object 后恢复；客户端断开或服务停止时清理进程树。
- Windows 终端需要 Windows 10 1809 / Server 2019 或更新版本的 ConPTY；不支持时明确失败。
- PowerShell 使用 `-Command`，cmd 使用 `/d /s /c`，Unix shell 使用 `-c`；CLI 与 Go 库采用一致的默认 shell。
- SFTP 使用服务进程的操作系统身份访问文件，不根据 SSH 用户名切换系统账户，也不提供文件系统沙箱。支持上传、下载、目录及重命名删除；Windows 可通过 `/C:/path` 访问盘符。

## 配置

程序启动时主动加载当前目录 `.env`；`run --env-file <绝对路径>` 指定独立文件并覆盖同名环境变量。不要将密码写入命令参数。授权公钥路径支持分号分隔，并兼容旧冒号格式，保留 Windows 盘符。

```dotenv
SSHDEV_LISTEN=0.0.0.0:2222
SSHDEV_PASSWORD=替换为独立强密码
# 或 SSHDEV_AUTHORIZED_KEYS_FILES=C:\keys\authorized_keys;D:\keys\authorized_keys
```

## 安装、自启与卸载

以管理员/root 执行，将 `.env` 预先写入配置目录：Windows 默认 `%ProgramData%\sshdev`，Linux 默认 `/etc/sshdev`，macOS 默认 `/Library/Application Support/sshdev`。可通过 `--config-dir` 指定独立绝对路径，`--name` 默认 `sshdev`。

```text
sshdev install --config-dir <配置目录>
sshdev status --config-dir <配置目录>
sshdev doctor --config-dir <配置目录>
sshdev uninstall --config-dir <配置目录>
```

- 安装将二进制复制到配置目录，首次生成独有 `host_key`，并把路径写回 `.env`；已有密钥严格验证并保留。安装拒绝无认证和共用内置主机密钥，禁止覆盖同名服务。
- 使用 Windows 原生服务（LocalSystem）、Linux 系统服务管理器等设置开机启动和失败恢复。Windows 收紧配置目录 ACL，并为非回环监听添加限定程序和端口的入站规则；Unix 防火墙由系统配置管理。
- 自检输出 JSON，包括认证配置、shell、主机指纹及监听状态；失败返回非零退出码。status 输出服务状态和版本。
- 卸载停止服务并移除其 Windows 防火墙规则，保留程序、`.env` 和主机密钥。升级由部署系统替换程序，不在 sshdev 内另设更新控制面。
- 日志不输出完整 CLI/服务配置。Linux 服务日志通过 `journalctl -u <服务名>` 查看。
- Android/Magisk 等未提供受支持系统服务管理器的环境继续由宿主自启入口运行 `run`。

## 验收

`task test:all` 运行全部 Go 测试，`task test:integration` 覆盖库及 CLI。GitHub `Cross-platform acceptance` 在 Ubuntu 与 Windows 实际运行竞态检测、SSH/SFTP/终端和转发测试，并构建 CLI 验证安装、密码与公钥登录、错误密码拒绝、自检、杀进程恢复和卸载。系统服务测试仅在 `SSHDEV_SERVICE_TEST=1` 的隔离 CI 中执行，避免修改开发机服务。
