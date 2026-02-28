# sshdev

一个简单的 SSH 服务器，适用于开发环境。可以作为 CLI 工具使用，也可以作为 Go 库使用。

## 作为 CLI 工具

### 编译
```bash
task build:bin
# 或者
go build -o sshdev ./cmd/sshdev
```

### 使用方式

#### 无认证模式（默认）
```bash
./sshdev run
```

#### 密码认证模式
```bash
SSHDEV_PASSWORD=secret ./sshdev run
```

#### 公钥认证模式
```bash
SSHDEV_AUTHORIZED_KEYS_FILES=~/.ssh/authorized_keys ./sshdev run
# 或直接指定公钥内容
SSHDEV_AUTHORIZED_KEYS="ssh-ed25519 AAAAC3..." ./sshdev run
```

#### 混合认证（密码 + 公钥）
```bash
SSHDEV_PASSWORD=secret SSHDEV_AUTHORIZED_KEYS_FILES=~/.ssh/authorized_keys ./sshdev run
```

#### 使用内置主机密钥
```bash
SSHDEV_HOST_KEY_BUILTIN=1 ./sshdev run
```

#### 连接服务器
```bash
ssh -p 2222 user@host
```

### 配置参数

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| SSHDEV_LISTEN | 监听地址 | `0.0.0.0:2222` |
| SSHDEV_PASSWORD | 认证密码（设置后启用密码认证） | - |
| SSHDEV_AUTHORIZED_KEYS_FILES | 授权公钥文件路径（冒号分隔） | - |
| SSHDEV_AUTHORIZED_KEYS | 授权公钥内容（换行分隔） | - |
| SSHDEV_HOST_KEY | 主机密钥内容（PEM 格式） | 随机生成 |
| SSHDEV_HOST_KEY_PATH | 主机密钥文件路径 | - |
| SSHDEV_HOST_KEY_BUILTIN | 使用内置主机密钥（任意非空值启用） | - |
| SSHDEV_SHELL | 默认 shell | 当前用户默认 shell |
| SSHDEV_CONFIG_JSON | JSON 格式完整配置 | - |

### 主机密钥优先级

1. `SSHDEV_HOST_KEY` - 环境变量指定的密钥内容
2. `SSHDEV_HOST_KEY_BUILTIN` - 内置的 ED25519 密钥
3. `SSHDEV_HOST_KEY_PATH` - 密钥文件路径
4. 随机生成 - 每次启动生成新密钥

## 作为 Go 库

### 安装
```bash
go get github.com/117503445/sshdev/pkg/sshlib
```

### 使用示例

```go
package main

import (
    "github.com/117503445/sshdev/pkg/sshlib"
)

func main() {
    cfg := &sshlib.Config{
        ListenAddr:     "0.0.0.0:2222",
        Password:       "secret",
        Shell:          "/bin/bash",
    }

    server, err := sshlib.NewServer(cfg)
    if err != nil {
        panic(err)
    }

    if err := server.Start(); err != nil {
        panic(err)
    }

    // 停止服务器：
    // server.Stop()
}
```

### 库 API

#### 类型
- `Config`: 服务器配置
- `Server`: 服务器接口，包含 Start() 和 Stop() 方法

#### 函数
- `NewServer(cfg *Config) (Server, error)`: 创建新的 SSH 服务器
- `DefaultAuthorizedKeysPath() string`: 返回默认的 authorized_keys 路径
- `Config.Validate() error`: 验证配置
- `Config.HasPasswordAuth() bool`: 是否启用密码认证
- `Config.HasPublicKeyAuth() bool`: 是否启用公钥认证

#### 错误
- `ErrInvalidConfig`: 配置无效时返回
- `ErrAuthenticationFailed`: 认证失败时返回