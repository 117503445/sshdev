package auth

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/117503445/sshdev/internal/types"
)

// testPubKeyLine 是测试用的 ed25519 公钥 authorized_keys 行。
const testPubKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example"

// fakeConnMetadata 是测试用的 ssh.ConnMetadata 实现。
type fakeConnMetadata struct{}

func (fakeConnMetadata) User() string          { return "test" }
func (fakeConnMetadata) SessionID() []byte     { return nil }
func (fakeConnMetadata) ClientVersion() []byte { return nil }
func (fakeConnMetadata) ServerVersion() []byte { return nil }
func (fakeConnMetadata) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (fakeConnMetadata) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}

// parseTestKey 解析测试公钥行。
func parseTestKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	return pubKey
}

// TestPublicKeyCallbackHotReload 验证认证回调每次重读 authorized_keys 文件：
// 启动时文件为空，追加公钥后无需重启即可通过认证。
func TestPublicKeyCallbackHotReload(t *testing.T) {
	keysPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(keysPath, nil, 0o600); err != nil {
		t.Fatalf("write empty authorized_keys: %v", err)
	}

	cfg := &types.Config{AuthorizedKeysFiles: keysPath}
	a, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	cb := a.PublicKeyCallback()
	if cb == nil {
		t.Fatal("PublicKeyCallback is nil for empty keys file")
	}

	key := parseTestKey(t, testPubKeyLine)
	if _, err := cb(fakeConnMetadata{}, key); err == nil {
		t.Fatal("auth succeeded before key was appended")
	}

	if err := os.WriteFile(keysPath, []byte(testPubKeyLine+"\n"), 0o600); err != nil {
		t.Fatalf("append authorized_keys: %v", err)
	}
	if _, err := cb(fakeConnMetadata{}, key); err != nil {
		t.Fatalf("auth failed after key was appended: %v", err)
	}
}

// TestPublicKeyCallbackDisabled 验证未配置公钥认证时回调为 nil。
func TestPublicKeyCallbackDisabled(t *testing.T) {
	a, err := NewAuthenticator(&types.Config{})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if cb := a.PublicKeyCallback(); cb != nil {
		t.Fatal("PublicKeyCallback should be nil without public key auth config")
	}
}

// TestPublicKeyCallbackContentKeys 验证 content 来源的公钥在启动时加载。
func TestPublicKeyCallbackContentKeys(t *testing.T) {
	cfg := &types.Config{AuthorizedKeys: testPubKeyLine}
	a, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	cb := a.PublicKeyCallback()
	if cb == nil {
		t.Fatal("PublicKeyCallback is nil")
	}
	if _, err := cb(fakeConnMetadata{}, parseTestKey(t, testPubKeyLine)); err != nil {
		t.Fatalf("auth failed with content key: %v", err)
	}
}
