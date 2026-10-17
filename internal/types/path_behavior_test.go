package types

import (
	"reflect"
	"testing"
)

// TestWindowsAuthorizedPaths 验证 input 中的 Windows 盘符不被当作分隔符；t 为测试上下文。
func TestWindowsAuthorizedPaths(t *testing.T) {
	for _, input := range []string{`C:\Users\test\.ssh\authorized_keys;D:\keys\allowed`, `C:\Users\test\.ssh\authorized_keys:D:\keys\allowed`} {
		want := []string{`C:\Users\test\.ssh\authorized_keys`, `D:\keys\allowed`}
		if got := ParseAuthorizedKeysFiles(input); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}
