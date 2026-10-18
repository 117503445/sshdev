package auth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/117503445/sshdev/internal/types"
	"golang.org/x/crypto/ssh"
)

// ValidateAuthorizedKeys 严格核验 files 路径和 content 中的全部授权公钥，返回有效数量。
func ValidateAuthorizedKeys(files, content string) (int, error) {
	sources := []string{content}
	for _, path := range types.ParseAuthorizedKeysFiles(files) {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("无法读取授权公钥文件 %s: %w", path, err)
		}
		sources = append(sources, string(data))
	}
	count := 0
	for index, source := range sources {
		scanner := bufio.NewScanner(strings.NewReader(source))
		line := 0
		for scanner.Scan() {
			line++
			text := strings.TrimSpace(scanner.Text())
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			if _, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(text)); err != nil || len(rest) > 0 {
				return count, fmt.Errorf("授权公钥来源 %d 第 %d 行无效", index+1, line)
			}
			count++
		}
		if err := scanner.Err(); err != nil {
			return count, err
		}
	}
	if (files != "" || content != "") && count == 0 {
		return 0, fmt.Errorf("已配置授权公钥，但没有有效公钥")
	}
	return count, nil
}
