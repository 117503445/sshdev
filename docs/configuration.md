# 环境变量配置

所有配置通过 `SSHDEV_` 前缀的环境变量设置。

## 核心配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SSHDEV_LISTEN` | 监听地址 | `0.0.0.0:2222` |
| `SSHDEV_PASSWORD` | 认证密码（设置后启用密码认证） | - |
| `SSHDEV_AUTHORIZED_KEYS_FILES` | 授权公钥文件路径（冒号分隔） | - |
| `SSHDEV_AUTHORIZED_KEYS` | 授权公钥内容（换行分隔） | - |
| `SSHDEV_HOST_KEY` | 主机密钥内容（PEM 格式） | 随机生成 |
| `SSHDEV_HOST_KEY_PATH` | 主机密钥文件路径 | - |
| `SSHDEV_SHELL` | 默认 shell（空则使用当前用户默认 shell） | - |
| `SSHDEV_CONFIG_JSON` | JSON 格式的完整配置 | - |

## 认证模式

认证模式根据配置自动确定：

- **无认证**：未设置 `SSHDEV_PASSWORD` 且未设置公钥配置
- **密码认证**：设置了 `SSHDEV_PASSWORD`
- **公钥认证**：设置了 `SSHDEV_AUTHORIZED_KEYS_FILES` 或 `SSHDEV_AUTHORIZED_KEYS`
- **混合认证**：同时设置了密码和公钥配置

## 命令行参数

```bash
./sshdev run --help
./sshdev run --listen=":2222" --password="secret"
```

## 示例

### 无认证模式（默认）

```bash
./sshdev run
```

### 密码认证

```bash
SSHDEV_PASSWORD=secret ./sshdev run
```

### 公钥认证

```bash
# 从文件读取公钥
SSHDEV_AUTHORIZED_KEYS_FILES="/home/user/.ssh/authorized_keys" ./sshdev run

# 直接指定公钥内容
SSHDEV_AUTHORIZED_KEYS="ssh-ed25519 AAAAC3..." ./sshdev run

# 多个公钥文件（冒号分隔）
SSHDEV_AUTHORIZED_KEYS_FILES="/home/user/.ssh/authorized_keys:/etc/ssh/authorized_keys" ./sshdev run
```

### 混合认证（密码 + 公钥）

```bash
SSHDEV_PASSWORD=secret SSHDEV_AUTHORIZED_KEYS_FILES="/home/user/.ssh/authorized_keys" ./sshdev run
```

### 使用 JSON 配置

```bash
SSHDEV_CONFIG_JSON='{"listenAddr":":2222","password":"secret","shell":"/bin/bash"}' ./sshdev run
```

### 指定监听地址

```bash
./sshdev run --listen="0.0.0.0:22"
```

### 指定主机密钥

```bash
# 从环境变量
SSHDEV_HOST_KEY="$(cat /path/to/host_key)" ./sshdev run

# 从文件路径
./sshdev run --host-key-path="/path/to/host_key"
```