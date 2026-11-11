package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// SecretBox 用 AES-256-GCM 加解密需要落库的凭据（主机密码、私钥口令等）。
// 密钥来源优先级：环境变量 CYBERSTRIKE_HOST_KEY（base64，32 字节）> 密钥文件。
// 密钥文件默认与数据库同目录，权限 0600，首次使用时自动生成。
type SecretBox struct {
	aead cipher.AEAD
}

var (
	secretBoxOnce sync.Once
	secretBoxInst *SecretBox
	secretBoxErr  error
)

// LoadSecretBox 返回进程级单例。
func LoadSecretBox(keyPath string) (*SecretBox, error) {
	secretBoxOnce.Do(func() {
		secretBoxInst, secretBoxErr = newSecretBox(keyPath)
	})
	return secretBoxInst, secretBoxErr
}

// ResetSecretBoxForTest 仅供测试使用，丢弃单例。
func ResetSecretBoxForTest() {
	secretBoxOnce = sync.Once{}
	secretBoxInst = nil
	secretBoxErr = nil
}

func newSecretBox(keyPath string) (*SecretBox, error) {
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化凭据加密失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化凭据加密失败: %w", err)
	}
	return &SecretBox{aead: aead}, nil
}

func loadOrCreateKey(keyPath string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv("CYBERSTRIKE_HOST_KEY")); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			return nil, errors.New("CYBERSTRIKE_HOST_KEY 必须是 32 字节密钥的 base64 编码")
		}
		return key, nil
	}
	if strings.TrimSpace(keyPath) == "" {
		keyPath = filepath.Join("data", "host_secret.key")
	}
	if data, err := os.ReadFile(keyPath); err == nil {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("凭据密钥文件损坏: %s", keyPath)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取凭据密钥失败: %w", err)
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("生成凭据密钥失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return nil, fmt.Errorf("创建凭据密钥目录失败: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("写入凭据密钥失败: %w", err)
	}
	return key, nil
}

// Encrypt 加密明文凭据，返回 base64(nonce||ciphertext)。空串保持为空。
func (s *SecretBox) Encrypt(plain string) (string, error) {
	if strings.TrimSpace(plain) == "" {
		return "", nil
	}
	if s == nil || s.aead == nil {
		return "", errors.New("凭据加密未初始化")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt 解密密文；密文为空时返回空串。
func (s *SecretBox) Decrypt(encoded string) (string, error) {
	if strings.TrimSpace(encoded) == "" {
		return "", nil
	}
	if s == nil || s.aead == nil {
		return "", errors.New("凭据加密未初始化")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("凭据密文格式错误: %w", err)
	}
	nonceSize := s.aead.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("凭据密文长度不足")
	}
	plain, err := s.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return "", errors.New("凭据解密失败：密钥可能已更换")
	}
	return string(plain), nil
}
