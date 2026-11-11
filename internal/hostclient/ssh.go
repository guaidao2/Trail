package hostclient

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// lockedBuffer 让 session.Run 的写入与取消/超时分支的读取互斥，
// 避免在 -race 下出现「后台 goroutine 仍在写、主 goroutine 已读」的数据竞争。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// execSSH 通过 SSH 会话执行命令。主机密钥默认接受（自建运维环境的常见做法），
// 但会把指纹回填到 ProbeResult，方便在界面里做首次信任核对。
func execSSH(ctx context.Context, opts Options, command string, timeout time.Duration) (*ExecResult, error) {
	if timeout <= 0 {
		timeout = opts.Timeout
	}
	started := time.Now()

	client, fingerprint, err := dialSSH(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建 SSH 会话失败: %w", err)
	}
	defer session.Close()

	var stdout, stderr lockedBuffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Duration: time.Since(started), HostKey: fingerprint},
			fmt.Errorf("命令执行被取消: %w", ctx.Err())
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return &ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Duration: time.Since(started), HostKey: fingerprint},
			fmt.Errorf("命令执行超时（%s）", timeout)
	case runErr := <-done:
		res := &ExecResult{
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			Duration: time.Since(started),
			HostKey:  fingerprint,
		}
		if runErr == nil {
			return res, nil
		}
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return res, fmt.Errorf("SSH 命令执行失败: %w", runErr)
	}
}

func dialSSH(ctx context.Context, opts Options) (*ssh.Client, string, error) {
	auths := make([]ssh.AuthMethod, 0, 2)
	if strings.TrimSpace(opts.Password) != "" {
		auths = append(auths, ssh.Password(opts.Password))
	}
	if strings.TrimSpace(opts.PrivateKey) != "" {
		var signer ssh.Signer
		var err error
		if strings.TrimSpace(opts.Passphrase) != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(opts.PrivateKey), []byte(opts.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(opts.PrivateKey))
		}
		if err != nil {
			return nil, "", fmt.Errorf("解析 SSH 私钥失败: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if len(auths) == 0 {
		return nil, "", fmt.Errorf("SSH 连接需要密码或私钥")
	}

	var fingerprint string
	cfg := &ssh.ClientConfig{
		User:    opts.Username,
		Auth:    auths,
		Timeout: opts.Timeout,
		HostKeyCallback: newHostKeyCallback(opts.HostKeyPin, &fingerprint),
	}

	dialer := net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", joinHostPort(opts.Address, opts.Port))
	if err != nil {
		return nil, "", fmt.Errorf("连接 %s 失败: %w", joinHostPort(opts.Address, opts.Port), err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, joinHostPort(opts.Address, opts.Port), cfg)
	if err != nil {
		_ = conn.Close()
		return nil, "", fmt.Errorf("SSH 握手失败: %w", err)
	}
	return ssh.NewClient(clientConn, chans, reqs), fingerprint, nil
}

// newHostKeyCallback 在校验主机密钥的同时记录本次指纹。
// 已固定（pin 非空）时要求指纹完全一致——这是首次信任（TOFU）的强制点，
// 也是凭据不会发给被替换主机的唯一保证。
func newHostKeyCallback(pin string, fingerprint *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if fingerprint != nil {
			*fingerprint = fp
		}
		return verifyHostKeyPin(pin, fp)
	}
}

func verifyHostKeyPin(pin, fingerprint string) error {
	if p := strings.TrimSpace(pin); p != "" && p != fingerprint {
		return fmt.Errorf("主机密钥不匹配：已记录 %s，本次为 %s", p, fingerprint)
	}
	return nil
}
