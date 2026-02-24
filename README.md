# dev-sshd

# 编译
make build-static

# 密码认证模式
SSHD_USERNAME=vscode SSHD_PASSWORD=secret ./dev-sshd

# 公钥认证模式
./dev-sshd --auth-mode=publickey --authorized-keys=~/.ssh/authorized_keys

# 无认证模式 (仅开发环境)
./dev-sshd --auth-mode=none

# 连接
ssh -p 2222 user@host

配置参数
环境变量	说明
SSHD_LISTEN	监听地址 (默认 0.0.0.0:2222)
SSHD_USERNAME	认证用户名
SSHD_PASSWORD	认证密码
SSHD_AUTH_MODE	认证模式 (password/publickey/none)
SSHD_HOST_KEY	Host key 文件路径
SSHD_SHELL	默认 shell (默认 /bin/bash)