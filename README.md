# sshdev

一个简单的 SSH 服务器，适用于开发环境。可以作为 CLI 工具使用，也可以作为 Go 库使用。

## 作为 CLI 工具

### 编译
```bash
task build:bin
# 或者
go build -o sshdev ./cmd/dev-sshd
```

### 使用方式

#### 密码认证模式
```bash
SSHDEV_USERNAME=vscode SSHDEV_PASSWORD=secret ./sshdev run
```

#### 公钥认证模式
```bash
./sshdev run --auth-mode=publickey --authorized-keys=~/.ssh/authorized_keys
```

#### 无认证模式（仅开发环境）
```bash
./sshdev run --auth-mode=none
```

#### 连接服务器
```bash
ssh -p 2222 user@host
```

### 配置参数

| 环境变量 | 说明 |
|---------|------|
| SSHDEV_LISTEN | 监听地址（默认：0.0.0.0:2222） |
| SSHDEV_USERNAME | 认证用户名 |
| SSHDEV_PASSWORD | 认证密码 |
| SSHDEV_AUTH_MODE | 认证模式（password/publickey/none/all） |
| SSHDEV_HOST_KEY | Host key 文件路径 |
| SSHDEV_SHELL | 默认 shell（默认：/bin/bash） |
| SSHDEV_AUTHORIZED_KEYS | 授权公钥文件路径 |

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
        HostKeyPath:    "./host_key",
        AuthMode:       sshlib.AuthModePassword,
        Username:       "user",
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
- `AuthMode`: 认证模式（Password、PublicKey、None、All）
- `Config`: 服务器配置
- `Server`: 服务器接口，包含 Start() 和 Stop() 方法

#### 函数
- `NewServer(cfg *Config) (Server, error)`: 创建新的 SSH 服务器
- `ParseAuthMode(s string) AuthMode`: 解析认证模式字符串
- `DefaultAuthorizedKeysPath() string`: 返回默认的 authorized_keys 路径
- `Config.Validate() error`: 验证配置

#### 错误
- `ErrInvalidConfig`: 配置无效时返回
- `ErrAuthenticationFailed`: 认证失败时返回