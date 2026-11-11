package hostclient

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Telnet 控制字节（RFC 854）。
const (
	telnetIAC  = 255
	telnetDONT = 254
	telnetDO   = 253
	telnetWONT = 252
	telnetWILL = 251
	telnetSB   = 250
	telnetSE   = 240
)

// execTelnet 走 Telnet 登录后执行命令。
//
// 输出捕获用哨兵标记而不是解析提示符：不同发行版提示符千差万别，
// 标记法只要 echo 能跑通就能稳定分界。
func execTelnet(ctx context.Context, opts Options, command string, timeout time.Duration) (*ExecResult, error) {
	if timeout <= 0 {
		timeout = opts.Timeout
	}
	started := time.Now()

	dialer := net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", joinHostPort(opts.Address, opts.Port))
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", joinHostPort(opts.Address, opts.Port), err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	reader := bufio.NewReader(conn)
	if err := telnetLogin(conn, reader, opts); err != nil {
		return &ExecResult{ExitCode: -1, Duration: time.Since(started)}, err
	}

	begin := "__CSAI_BEGIN_" + randomToken() + "__"
	end := "__CSAI_END_" + randomToken() + "__"
	script := fmt.Sprintf("echo %s; %s; echo %s\n", begin, command, end)

	if _, err := conn.Write([]byte(script)); err != nil {
		return &ExecResult{ExitCode: -1, Duration: time.Since(started)}, fmt.Errorf("发送命令失败: %w", err)
	}

	output, err := readUntilMarker(reader, begin, end, deadline)
	res := &ExecResult{Stdout: output, Duration: time.Since(started)}
	if err != nil {
		res.ExitCode = -1
		return res, err
	}
	return res, nil
}

// telnetLogin 完成 IAC 协商与登录流程（有用户名/密码时才发送）。
func telnetLogin(conn net.Conn, reader *bufio.Reader, opts Options) error {
	var transcript strings.Builder
	deadlineReached := false
	buf := make([]byte, 512)

	for i := 0; i < 40; i++ {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if reply := telnetNegotiationReply(chunk); len(reply) > 0 {
				_, _ = conn.Write(reply)
			}
			transcript.WriteString(stripTelnetIAC(chunk))
			lower := strings.ToLower(transcript.String())
			switch {
			case opts.Username != "" && strings.Contains(lower, "login:") && !strings.Contains(lower, opts.Username+":"):
				if _, err := conn.Write([]byte(opts.Username + "\n")); err != nil {
					return fmt.Errorf("发送用户名失败: %w", err)
				}
				transcript.Reset()
				// 登录名回显后可能再次出现 login: 提示，这里只发送一次
				opts.Username = ""
			case opts.Password != "" && (strings.Contains(lower, "password:") || strings.Contains(lower, "口令")):
				if _, err := conn.Write([]byte(opts.Password + "\n")); err != nil {
					return fmt.Errorf("发送密码失败: %w", err)
				}
				transcript.Reset()
				opts.Password = ""
			}
		}
		if err != nil {
			deadlineReached = true
			break
		}
		// 已经没有任何需要发送的凭据，视为登录流程结束
		if opts.Username == "" && opts.Password == "" {
			return nil
		}
	}
	if deadlineReached {
		return fmt.Errorf("Telnet 登录超时")
	}
	return nil
}

func randomToken() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// stripTelnetIAC 去掉 IAC 命令序列，只保留可读文本。
func stripTelnetIAC(raw []byte) string {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b != telnetIAC {
			if b == '\r' {
				continue
			}
			out = append(out, b)
			continue
		}
		if i+1 >= len(raw) {
			break
		}
		cmd := raw[i+1]
		switch cmd {
		case telnetWILL, telnetWONT, telnetDO, telnetDONT:
			// 后面跟一个选项字节
			i += 2
		case telnetSB:
			// 子协商：跳到 IAC SE
			i += 2
			for i+1 < len(raw) {
				if raw[i] == telnetIAC && raw[i+1] == telnetSE {
					i++
					break
				}
				i++
			}
		default:
			i++
		}
	}
	return string(out)
}

// telnetNegotiationReply 对 DO/WILL 统一回 DONT/WONT，避免服务端坚持协商。
func telnetNegotiationReply(raw []byte) []byte {
	reply := make([]byte, 0, 9)
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != telnetIAC {
			continue
		}
		switch raw[i+1] {
		case telnetDO:
			reply = append(reply, telnetIAC, telnetWONT, raw[i+2])
		case telnetWILL:
			reply = append(reply, telnetIAC, telnetDONT, raw[i+2])
		}
	}
	return reply
}

// readUntilMarker 读取输出直到结束标记，返回两个标记之间的内容。
func readUntilMarker(reader *bufio.Reader, begin, end string, deadline time.Time) (string, error) {
	var collected strings.Builder
	buf := make([]byte, 1024)
	for time.Now().Before(deadline) {
		n, err := reader.Read(buf)
		if n > 0 {
			collected.WriteString(stripTelnetIAC(buf[:n]))
			text := collected.String()
			if start := strings.Index(text, begin); start >= 0 {
				rest := text[start+len(begin):]
				if stop := strings.Index(rest, end); stop >= 0 {
					return cleanTelnetOutput(rest[:stop]), nil
				}
			}
		}
		if err != nil {
			break
		}
	}
	return cleanTelnetOutput(collected.String()), fmt.Errorf("等待命令结束标记超时")
}

var telnetEchoMarker = regexp.MustCompile(`(?m)^\s*(echo\s+__CSAI_|.*__CSAI_(BEGIN|END)_[0-9]+__.*)\s*$`)

// cleanTelnetOutput 去掉回显的脚本行与首尾空白。
func cleanTelnetOutput(s string) string {
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if telnetEchoMarker.MatchString(line) {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, strings.TrimRight(line, "\r"))
	}
	return strings.Join(kept, "\n")
}
