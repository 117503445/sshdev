# 重构日志使用 context

## 主要内容和目的

将项目中所有日志打印从 `log.Info/Warn/Error` 改为使用 `log.Ctx(ctx)` 模式，以支持上下文感知的日志记录和追踪。

## 更改内容描述

### 核心变更

1. **[internal/auth/auth.go](../../internal/auth/auth.go)**:
   - `Authenticator` 结构体添加 `ctx` 字段
   - 新增 `NewAuthenticatorWithContext` 函数
   - 所有认证日志改用 `log.Ctx(ctx)` 模式

2. **[internal/server/server.go](../../internal/server/server.go)**:
   - `NewServer` 和 `Start` 方法中的日志改用 `log.Ctx(ctx)`

3. **[cmd/sshdev/cli.go](../../cmd/sshdev/cli.go)**:
   - `Run` 方法创建并传递 `ctx` 到所有日志调用
   - `defaultShell` 函数添加 `ctx` 参数

4. **[cmd/sshdev/main.go](../../cmd/sshdev/main.go)**:
   - 使用全局 `Ctx` 变量传递给 `log.Ctx(Ctx)`

5. **[pkg/sshlib/server_impl.go](../../pkg/sshlib/server_impl.go)**:
   - `validateConfig` 函数添加 `ctx` 参数

6. **[pkg/sshlib/server.go](../../pkg/sshlib/server.go)**:
   - `Validate` 方法添加 `ctx` 参数
   - `NewServer` 传递 `context.Background()` 给 `Validate`

7. **[pkg/sshlib/server_test.go](../../pkg/sshlib/server_test.go)**:
   - 更新测试以适配新的 `Validate` 签名

## 验证方法和结果

- 运行 `go build ./...` 编译成功
- 运行 `go test ./...` 所有测试通过