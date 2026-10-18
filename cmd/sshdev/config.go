package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/117503445/sshdev/pkg/sshlib"
	"github.com/joho/godotenv"
)

// ConfigOptions 用指针区分未设置与显式空值/false，供运行、安装和诊断复用。
type ConfigOptions struct {
	ListenAddr          *string `name:"listen" help:"监听地址" json:"listenAddr" key:"SSHDEV_LISTEN"`
	HostKeyPath         *string `name:"host-key" help:"主机密钥文件" json:"hostKeyPath" key:"SSHDEV_HOST_KEY_PATH"`
	HostKeyContent      *string `name:"host-key-content" help:"主机密钥内容" json:"hostKeyContent" key:"SSHDEV_HOST_KEY"`
	HostKeyBuiltin      *bool   `name:"host-key-builtin" help:"使用内置测试密钥" json:"hostKeyBuiltin" key:"SSHDEV_HOST_KEY_BUILTIN"`
	Password            *string `name:"password" help:"认证密码" json:"password" key:"SSHDEV_PASSWORD"`
	AuthorizedKeysFiles *string `name:"authorized-keys-files" help:"授权公钥文件列表" json:"authorizedKeysFiles" key:"SSHDEV_AUTHORIZED_KEYS_FILES"`
	AuthorizedKeys      *string `name:"authorized-keys" help:"授权公钥内容" json:"authorizedKeys" key:"SSHDEV_AUTHORIZED_KEYS"`
	Insecure            *bool   `name:"insecure" help:"显式允许无认证" json:"insecure" key:"SSHDEV_INSECURE"`
	Shell               *string `name:"shell" help:"会话 shell" json:"shell" key:"SSHDEV_SHELL"`
	Pinggy              *bool   `name:"pinggy" help:"启用 Pinggy 隧道" json:"pinggy" key:"SSHDEV_PINGGY"`
	ConfigJSON          *string `name:"config-json" help:"JSON 配置" json:"-"`
}

// resolvedConfig 保存最终生效的服务和隧道配置。
type resolvedConfig struct {
	Config *sshlib.Config
	Pinggy bool
}

// environmentValues 读取当前进程环境，不修改全局环境。
func environmentValues() map[string]string {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	return values
}

// resolveConfig 按默认值、JSON、values 环境、options 显式参数的顺序解析配置。
func resolveConfig(options ConfigOptions, values map[string]string) (resolvedConfig, error) {
	parsed := ConfigOptions{}
	raw := values["SSHDEV_CONFIG_JSON"]
	if options.ConfigJSON != nil {
		raw = *options.ConfigJSON
	}
	if raw != "" {
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&parsed); err != nil {
			return resolvedConfig{}, fmt.Errorf("JSON 配置无效: %w", err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return resolvedConfig{}, fmt.Errorf("JSON 配置必须只有一个对象")
		}
	}
	target := reflect.ValueOf(&parsed).Elem()
	kind := target.Type()
	for i := 0; i < target.NumField(); i++ {
		key := kind.Field(i).Tag.Get("key")
		if key == "" {
			continue
		}
		raw, ok := values[key]
		if !ok {
			continue
		}
		value := reflect.New(target.Field(i).Type().Elem())
		if value.Elem().Kind() == reflect.Bool {
			boolean := false
			var err error
			if raw != "" {
				boolean, err = strconv.ParseBool(raw)
			}
			if err != nil {
				return resolvedConfig{}, fmt.Errorf("%s 必须是布尔值", key)
			}
			value.Elem().SetBool(boolean)
		} else {
			value.Elem().SetString(raw)
		}
		target.Field(i).Set(value)
	}
	overrides := reflect.ValueOf(options)
	for i := 0; i < target.NumField(); i++ {
		if !overrides.Field(i).IsNil() {
			target.Field(i).Set(overrides.Field(i))
		}
	}
	cfg := &sshlib.Config{ListenAddr: "0.0.0.0:2222", Version: Version}
	out := reflect.ValueOf(cfg).Elem()
	for i := 0; i < target.NumField(); i++ {
		field := target.Field(i)
		if field.IsNil() {
			continue
		}
		destination := out.FieldByName(kind.Field(i).Name)
		if destination.IsValid() {
			destination.Set(field.Elem())
		}
	}
	if cfg.Shell == "" {
		cfg.Shell = defaultShell(context.Background())
	}
	if _, _, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		return resolvedConfig{}, fmt.Errorf("监听地址无效: %w", err)
	}
	return resolvedConfig{Config: cfg, Pinggy: parsed.Pinggy != nil && *parsed.Pinggy}, nil
}

// serviceValues 读取 path 的配置，并按显式 .env 语义覆盖当前环境；返回原文件和合并环境。
func serviceValues(path string) (map[string]string, map[string]string, error) {
	file, err := godotenv.Read(path)
	if err != nil {
		return nil, nil, err
	}
	values := environmentValues()
	for key, value := range file {
		values[key] = value
	}
	return file, values, nil
}

// persistConfig 把 resolved 的实际配置写入 values，防止服务启动时再次受到 JSON 或环境残留影响。
func persistConfig(values map[string]string, resolved resolvedConfig) {
	cfg := reflect.ValueOf(resolved.Config).Elem()
	options := reflect.TypeOf(ConfigOptions{})
	for i := 0; i < options.NumField(); i++ {
		field := options.Field(i)
		key := field.Tag.Get("key")
		if key == "" {
			continue
		}
		value := cfg.FieldByName(field.Name)
		if field.Name == "Pinggy" {
			values[key] = strconv.FormatBool(resolved.Pinggy)
		} else if value.Kind() == reflect.Bool {
			values[key] = strconv.FormatBool(value.Bool())
		} else {
			values[key] = value.String()
		}
	}
	values["SSHDEV_CONFIG_JSON"] = ""
}
