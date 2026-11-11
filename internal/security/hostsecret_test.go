package security

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func newTestSecretBox(t *testing.T, keyFile string) *SecretBox {
	t.Helper()
	ResetSecretBoxForTest()
	t.Cleanup(ResetSecretBoxForTest)
	box, err := LoadSecretBox(keyFile)
	if err != nil {
		t.Fatalf("LoadSecretBox: %v", err)
	}
	return box
}

func TestSecretBoxRoundTrip(t *testing.T) {
	box := newTestSecretBox(t, filepath.Join(t.TempDir(), "host_secret.key"))

	secret := "s3cr3t-p@ssw0rd"
	cipherText, err := box.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if cipherText == "" || cipherText == secret {
		t.Fatalf("ciphertext looks wrong: %q", cipherText)
	}

	plain, err := box.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != secret {
		t.Fatalf("round trip = %q, want %q", plain, secret)
	}

	// 同一明文两次加密必须产生不同密文（随机 nonce）
	second, err := box.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt again: %v", err)
	}
	if second == cipherText {
		t.Fatal("two encryptions produced identical ciphertext; nonce is not random")
	}
}

func TestSecretBoxEmptyValues(t *testing.T) {
	box := newTestSecretBox(t, filepath.Join(t.TempDir(), "host_secret.key"))
	enc, err := box.Encrypt("")
	if err != nil || enc != "" {
		t.Fatalf("Encrypt(\"\") = %q, %v; want empty, nil", enc, err)
	}
	dec, err := box.Decrypt("")
	if err != nil || dec != "" {
		t.Fatalf("Decrypt(\"\") = %q, %v; want empty, nil", dec, err)
	}
}

func TestSecretBoxRejectsForeignKey(t *testing.T) {
	dir := t.TempDir()
	box := newTestSecretBox(t, filepath.Join(dir, "a.key"))
	cipherText, err := box.Encrypt("hunter2")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	other := newTestSecretBox(t, filepath.Join(dir, "b.key"))
	if _, err := other.Decrypt(cipherText); err == nil {
		t.Fatal("decrypting with a different key must fail")
	}
}

func TestSecretBoxKeyFileIsPersistedAndPrivate(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "nested", "host_secret.key")
	box := newTestSecretBox(t, keyPath)
	cipherText, err := box.Encrypt("value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	// Windows 不实现 POSIX 权限位（os.WriteFile 的 0600 会呈现为 0666），
	// 权限收紧只在类 Unix 上可验证。
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Fatalf("key file permission = %o, want owner-only", perm)
		}
	}

	// 重新加载同一个密钥文件后仍能解密
	reloaded := newTestSecretBox(t, keyPath)
	plain, err := reloaded.Decrypt(cipherText)
	if err != nil || plain != "value" {
		t.Fatalf("reload decrypt = %q, %v", plain, err)
	}
}

func TestSecretBoxUsesEnvKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("CYBERSTRIKE_HOST_KEY", base64.StdEncoding.EncodeToString(key))

	box := newTestSecretBox(t, filepath.Join(t.TempDir(), "ignored.key"))
	cipherText, err := box.Encrypt("from-env")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 换一个进程级实例，仅靠同一个环境变量密钥也能解开
	ResetSecretBoxForTest()
	box2, err := LoadSecretBox(filepath.Join(t.TempDir(), "ignored2.key"))
	if err != nil {
		t.Fatalf("LoadSecretBox: %v", err)
	}
	plain, err := box2.Decrypt(cipherText)
	if err != nil || plain != "from-env" {
		t.Fatalf("env key decrypt = %q, %v", plain, err)
	}
}

func TestSecretBoxRejectsBadEnvKey(t *testing.T) {
	t.Setenv("CYBERSTRIKE_HOST_KEY", base64.StdEncoding.EncodeToString([]byte("too-short")))
	ResetSecretBoxForTest()
	t.Cleanup(ResetSecretBoxForTest)
	if _, err := LoadSecretBox(filepath.Join(t.TempDir(), "k.key")); err == nil {
		t.Fatal("expected an error for a short env key")
	}
}
