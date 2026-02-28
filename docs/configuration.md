# 环境变量配置

所有配置通过 `SSHDEV_` 前缀的环境变量设置。

## 核心配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SSHDEV_LISTEN` | 监听地址 | `:2222` |
| `SSHDEV_USERNAME` | 认证用户名 | - |
| `SSHDEV_PASSWORD` | 认证密码 | - |
| `SSHDEV_HOST_KEY` | 主机密钥文件路径 | - |
| `SSHDEV_AUTH_MODE` | 认证模式 (`password`/`none`) | `password` |

## 命令行参数

```bash
./sshdev run --help
./sshdev run --listen=":2222" --host-key="./host_key" --auth-mode="password"
```

## 示例

```bash
# 密码认证
SSHDEV_USERNAME=admin SSHDEV_PASSWORD=secret ./sshdev run

# 无认证（测试用）
./sshdev run --auth-mode="none"

# 指定监听地址
./sshdev run --listen="0.0.0.0:22"
```