# 项目架构

## 目录结构

```
sshdev/
├── cmd/sshdev/          # CLI 入口点
├── pkg/sshlib/          # 公共库 API（对外暴露 Server 接口）
├── internal/            # 内部实现
│   ├── auth/            # 认证模块
│   ├── buildinfo/       # 构建信息
│   ├── server/          # SSH 服务器核心
│   ├── session/         # 会话管理
│   ├── types/           # 类型定义
│   └── utils/           # 工具函数
├── scripts/             # 构建脚本
│   ├── script/          # 脚本文件
│   └── tasks/           # Taskfile 任务定义
└── data/                # 输出目录
    ├── cli/             # 本地构建输出
    └── release/         # 发布版本输出
```

## 核心模块

### pkg/sshlib

对外暴露的公共 API，包含 `Server` 接口及其实现。

### internal/server

SSH 服务器核心逻辑，处理连接、认证、会话。

### internal/session

会话管理，包括 PTY、Shell、端口转发等。

### internal/auth

认证模块，支持密码认证和无认证模式。

### internal/types

共享类型定义。

### internal/utils

日志、错误处理等工具函数。