# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# WORKFLOW

收到任务后立即执行：

1. 分析用户请求
2. 运行 `find docs/ -name "*.md" | sort` 查看可用文档
3. 阅读与当前任务相关的文档
4. 制定执行计划，向用户确认
5. 用户确认后执行任务
6. 任务执行完毕，更新文档，向用户报告结果

# KEY FILES

- `docs/build-test.md` - 构建与测试命令
- `docs/architecture.md` - 项目架构
- `docs/configuration.md` - 环境变量配置
- `docs/development.md` - 开发注意事项
- `Taskfile.yml` - 构建任务定义

# REMEMBER

- 使用 Task (Taskfile)，不是 Make
- 日志库: zerolog，默认级别 Debug，使用 ctx
- 环境变量前缀: `SSHDEV_`