package main

import (
	"testing"

	"github.com/alecthomas/kong"
)

// parseOptions 使用真实 CLI 解析 args，验证参数是否确实被显式设置；t 为测试上下文。
func parseOptions(t *testing.T, args ...string) ConfigOptions {
	t.Helper()
	var options ConfigOptions
	parser, err := kong.New(&options, kong.Exit(func(int) { t.Fatal("CLI 解析退出") }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parser.Parse(args); err != nil {
		t.Fatal(err)
	}
	return options
}

// TestConfigPrecedence 验证 JSON、环境与显式 CLI 的优先级和空值/false；t 为测试上下文。
func TestConfigPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		args     []string
		listen   string
		insecure bool
		password string
	}{
		{name: "JSON保留监听", env: map[string]string{"SSHDEV_CONFIG_JSON": `{"listenAddr":"127.0.0.1:4567","insecure":true}`}, listen: "127.0.0.1:4567", insecure: true},
		{name: "环境覆盖JSON", env: map[string]string{"SSHDEV_CONFIG_JSON": `{"listenAddr":":4567","insecure":true}`, "SSHDEV_LISTEN": ":4568", "SSHDEV_INSECURE": "false"}, listen: ":4568"},
		{name: "显式false覆盖环境", env: map[string]string{"SSHDEV_INSECURE": "true", "SSHDEV_PASSWORD": "old"}, args: []string{"--listen=:4569", "--insecure=false", "--password="}, listen: ":4569"},
		{name: "CLI_JSON低于字段环境", env: map[string]string{"SSHDEV_LISTEN": ":4568"}, args: []string{"--config-json", `{"listenAddr":":4567"}`}, listen: ":4568"},
		{name: "默认值", env: map[string]string{}, listen: "0.0.0.0:2222"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveConfig(parseOptions(t, test.args...), test.env)
			if err != nil {
				t.Fatal(err)
			}
			if got.Config.ListenAddr != test.listen || got.Config.Insecure != test.insecure || got.Config.Password != test.password {
				t.Fatalf("解析结果不符: listen=%q insecure=%v", got.Config.ListenAddr, got.Config.Insecure)
			}
		})
	}
}

// TestInvalidConfigRejected 验证错误 JSON、未知字段和无效布尔值立即失败；t 为测试上下文。
func TestInvalidConfigRejected(t *testing.T) {
	for _, raw := range []string{"{", `{"insecure":"true"}`, `{"unknown":true}`, `{} {}`, `[]`} {
		if _, err := resolveConfig(ConfigOptions{}, map[string]string{"SSHDEV_CONFIG_JSON": raw}); err == nil {
			t.Errorf("无效JSON被接受: %s", raw)
		}
	}
	if _, err := resolveConfig(ConfigOptions{}, map[string]string{"SSHDEV_INSECURE": "invalid"}); err == nil {
		t.Fatal("无效布尔值被接受")
	}
}
