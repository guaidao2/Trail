// Package hostclient 提供纳管主机的远程执行能力：SSH（密码 / 私钥）与 Telnet。
//
// 设计取舍：
//   - 不引入 SFTP 依赖，文件传输走 SSH exec 通道的 base64 管道，够运维传配置、
//     取日志；真正的批量同步后续可换 rsync/sftp。
//   - Telnet 只做「登录 + 执行 + 取回输出」，不做交互式全屏应用（vi/top 之类）。
//   - 所有操作都带超时，避免半死连接把 Agent 的单轮执行拖住。
package hostclient

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Options 描述一次远程连接所需的全部信息。凭据由调用方解密后传入，
// 本包不负责存储与加解密。
type Options struct {
	Protocol   string // ssh | telnet
	Address    string
	Port       int
	Username   string
	Password   string
	PrivateKey string // PEM，auth_type=key 时使用
	Passphrase string // 私钥口令，可空
	Timeout    time.Duration
	// HostKeyPin 是首次信任记录下来的主机密钥指纹（SHA256）。非空时强制校验：
	// 指纹不一致直接拒绝连接，避免把存储的凭据发给被替换的主机。
	HostKeyPin string
}

// ExecResult 是一次远程命令的执行结果。
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	HostKey  string // 远端主机密钥指纹（SHA256），首次连接时可核对
}

// ProbeResult 是一次连通性与基础信息探测的结果。
type ProbeResult struct {
	Online         bool
	OSInfo         string
	HostKey        string
	Error          string
	Duration       time.Duration
	RemoteUser     string
	RemoteHostname string
}

func (o Options) normalized() Options {
	out := o
	out.Protocol = strings.ToLower(strings.TrimSpace(o.Protocol))
	if out.Protocol == "" {
		out.Protocol = "ssh"
	}
	if out.Port <= 0 {
		if out.Protocol == "telnet" {
			out.Port = 23
		} else {
			out.Port = 22
		}
	}
	if out.Timeout <= 0 {
		out.Timeout = 20 * time.Second
	}
	out.Address = strings.TrimSpace(out.Address)
	out.Username = strings.TrimSpace(out.Username)
	return out
}

// Validate 在发起连接前做一次快速校验，错误信息面向运维可读。
func (o Options) Validate() error {
	n := o.normalized()
	if n.Address == "" {
		return fmt.Errorf("主机地址不能为空")
	}
	if n.Protocol != "ssh" && n.Protocol != "telnet" {
		return fmt.Errorf("不支持的协议: %s", n.Protocol)
	}
	if n.Protocol == "ssh" {
		if n.Username == "" {
			return fmt.Errorf("SSH 连接需要用户名")
		}
		if strings.TrimSpace(n.Password) == "" && strings.TrimSpace(n.PrivateKey) == "" {
			return fmt.Errorf("SSH 连接需要密码或私钥")
		}
	}
	return nil
}

func joinHostPort(address string, port int) string {
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") && strings.Count(address, ":") > 1 {
		// 裸 IPv6 地址需要加方括号
		return "[" + address + "]:" + strconv.Itoa(port)
	}
	return address + ":" + strconv.Itoa(port)
}

// Exec 在远程主机上执行一条命令（ssh / telnet 自动分派）。
func Exec(ctx context.Context, opts Options, command string, timeout time.Duration) (*ExecResult, error) {
	n := opts.normalized()
	if err := n.Validate(); err != nil {
		return nil, err
	}
	switch n.Protocol {
	case "ssh":
		return execSSH(ctx, n, command, timeout)
	case "telnet":
		return execTelnet(ctx, n, command, timeout)
	default:
		return nil, fmt.Errorf("不支持的协议: %s", n.Protocol)
	}
}

// Probe 探测连通性并取回基础信息（不需要调用方再单独跑 uname）。
func Probe(ctx context.Context, opts Options) (*ProbeResult, error) {
	n := opts.normalized()
	if err := n.Validate(); err != nil {
		return &ProbeResult{Online: false, Error: err.Error()}, err
	}
	started := time.Now()
	cmd := `echo "__CSAI_OS__$(uname -srm 2>/dev/null || echo unknown)"; echo "__CSAI_OSREL__$( (cat /etc/os-release 2>/dev/null | head -2 | tr '\n' ' ') || echo unknown)"; echo "__CSAI_USER__$(id -un 2>/dev/null || whoami 2>/dev/null)"; echo "__CSAI_HOST__$(hostname 2>/dev/null)"`
	res, err := Exec(ctx, n, cmd, n.Timeout)
	elapsed := time.Since(started)
	out := &ProbeResult{Duration: elapsed}
	if err != nil {
		out.Online = false
		out.Error = err.Error()
		return out, err
	}
	out.Online = true
	out.HostKey = res.HostKey
	fields := parseProbeOutput(res.Stdout)
	out.OSInfo = strings.TrimSpace(fields["OS"] + " " + fields["OSREL"])
	out.RemoteUser = fields["USER"]
	out.RemoteHostname = fields["HOST"]
	if out.OSInfo == "" {
		out.OSInfo = "unknown"
	}
	return out, nil
}

func parseProbeOutput(stdout string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "__CSAI_") {
			continue
		}
		rest := strings.TrimPrefix(line, "__CSAI_")
		idx := strings.Index(rest, "__")
		if idx < 0 {
			continue
		}
		key, value := rest[:idx], rest[idx+2:]
		fields[key] = strings.TrimSpace(value)
	}
	return fields
}
