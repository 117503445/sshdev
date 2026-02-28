# 构建与测试

## Taskfile 命令

项目使用 [Task](https://taskfile.dev/) 作为构建工具。

### 构建

```bash
task build:bin          # 构建二进制文件 -> ./data/cli/sshdev
task build:release      # 构建多平台发布版本 -> ./data/release/
task build:linux        # 构建 Linux AMD64 静态二进制
task build:docker       # 构建 Docker 镜像
```

### 测试

```bash
task test:all           # 运行所有测试
task test:unit          # 仅运行单元测试 (internal/...)
task test:integration   # 运行集成测试
task test:coverage      # 测试覆盖率报告
task test:race          # 竞态检测测试
```

### 格式化

```bash
task format:all         # 格式化并检查代码 (go fmt + go vet)
```

### 开发运行

```bash
task run:dev            # 开发模式运行 (用户名/密码: test/test)
task run:noauth         # 无认证模式运行
task run:local          # 本地配置运行
```

## Go 命令

```bash
go build -o ./sshdev ./cmd/sshdev    # 直接构建
go test ./... -v                     # 运行测试
go fmt ./...                         # 格式化代码
```