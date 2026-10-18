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

`run`、`install` 和 `doctor` 共用解析器，字段优先级为：默认值 < JSON < 环境变量 < 显式命令参数。`--config-json` 替换 `SSHDEV_CONFIG_JSON` 的 JSON 来源，字段环境变量仍优先于 JSON。显式空字符串和 `--insecure=false` 会覆盖此前值；错误 JSON、未知字段和错误布尔值立即失败。`install`、`doctor` 读取配置目录 `.env`，该文件覆盖同名进程环境；安装将最终字段写回文件，清空 JSON，确保服务重启使用同一结果。

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
- 自检输出 JSON，核验 shell、授权公钥格式及文件可读性，执行实际 SSH 握手并比对配置中的主机密钥和运行版本，其他程序占用端口不会通过。默认要求运行版本等于当前 doctor 版本，可用 `--expected-version` 指定；`--timeout` 限制连接及握手总时长。
- 配置密码时，自检还验证密码登录。仅配置公钥时，默认验证签名握手和主机身份，`authenticationVerified` 为 false；使用 `doctor --identity <私钥路径>` 可进一步验证公钥登录。status 输出服务管理器状态与本地程序版本。
- 卸载停止服务并移除其 Windows 防火墙规则，保留程序、`.env` 和主机密钥。升级由部署系统替换程序，不在 sshdev 内另设更新控制面。
- 日志不输出完整 CLI/服务配置。Linux 服务日志通过 `journalctl -u <服务名>` 查看。
- Android/Magisk 等未提供受支持系统服务管理器的环境继续由宿主自启入口运行 `run`。

## 验收

`task test:all` 运行全部 Go 测试，`task test:integration` 覆盖库及 CLI。GitHub `Cross-platform acceptance` 同时作为发布门禁：

- Ubuntu、Windows、macOS 15 原生 runner 运行竞态检测、SSH/SFTP/PTY/信号及转发测试；使用实际 OpenSSH `ssh`、`sftp`、`scp` 验证退出码、独立错误输出、中文和空格路径、传输校验及双向端口转发。
- Windows 使用真实 WinSCP 6.5.3 执行 SFTP 目录、上传下载、重命名和删除。
- Ubuntu 使用真实 VS Code 1.107.1 与 Remote SSH 0.120.0，验证远程文件创建、编辑保存和集成终端，保留结果、日志及 Electron 窗口截图。该编辑器版本包含上游扩展安装 CLI 崩溃修复（microsoft/vscode#279806）。
- Ubuntu、Windows 验证系统服务安装、自启、密码与公钥登录、错误认证拒绝、自检、杀进程恢复和卸载。系统服务测试仅在 `SSHDEV_SERVICE_TEST=1` 的隔离 CI 中执行；macOS 当前覆盖运行与客户端，不覆盖 launchd 安装。

CI 使用独占回环服务和临时凭据，不连接现有设备；制品仅保存客户端日志与编辑器证据，不上传 `.env` 或私钥。
