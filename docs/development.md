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