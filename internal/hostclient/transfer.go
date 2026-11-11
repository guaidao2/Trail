package hostclient

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 文件传输走 SSH exec 的 base64 管道：不引入 SFTP 依赖，也避免在目标机留下临时脚本。
// 代价是内容会被 base64 放大 33%，因此对单次传输大小设上限。

// MaxTransferBytes 是一次传输允许的最大原始字节数（默认 8 MiB，base64 后约 11 MiB）。
const MaxTransferBytes = 8 << 20

// UploadFile 把内容写到远程路径（自动创建父目录，覆盖已有文件）。
func UploadFile(ctx context.Context, opts Options, remotePath string, content []byte, mode string) error {
	if opts.normalized().Protocol != "ssh" {
		return fmt.Errorf("文件传输目前仅支持 SSH")
	}
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return fmt.Errorf("远程路径不能为空")
	}
	if len(content) > MaxTransferBytes {
		return fmt.Errorf("文件过大（%d 字节），单次上限 %d 字节", len(content), MaxTransferBytes)
	}
	if mode == "" {
		mode = "600"
	}
	script := buildUploadScript(remotePath, content, mode)
	res, err := Exec(ctx, opts, script, 2*time.Minute)
	if err != nil {
		return fmt.Errorf("上传失败: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("上传失败（退出码 %d）: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// DownloadFile 读取远程文件内容。
func DownloadFile(ctx context.Context, opts Options, remotePath string) ([]byte, error) {
	if opts.normalized().Protocol != "ssh" {
		return nil, fmt.Errorf("文件传输目前仅支持 SSH")
	}
	remotePath = strings.TrimSpace(remotePath)
	if remotePath == "" {
		return nil, fmt.Errorf("远程路径不能为空")
	}
	// 先确认远端文件大小，避免把超大文件整体 base64 进内存后再拒绝。
	statScript := fmt.Sprintf("stat -c %%s %s 2>/dev/null || wc -c < %s", shellQuote(remotePath), shellQuote(remotePath))
	statRes, statErr := Exec(ctx, opts, statScript, 30*time.Second)
	if statErr == nil && statRes.ExitCode == 0 {
		if size, err := strconv.ParseInt(strings.TrimSpace(statRes.Stdout), 10, 64); err == nil && size > MaxTransferBytes {
			return nil, fmt.Errorf("文件过大（%d 字节），单次上限 %d 字节", size, MaxTransferBytes)
		}
	}
	script := fmt.Sprintf("base64 < %s", shellQuote(remotePath))
	res, err := Exec(ctx, opts, script, 2*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("下载失败: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("下载失败（退出码 %d）: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	cleaned := stripWhitespace(res.Stdout)
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("远程返回内容不是合法 base64: %w", err)
	}
	if len(decoded) > MaxTransferBytes {
		return nil, fmt.Errorf("文件过大（%d 字节），单次上限 %d 字节", len(decoded), MaxTransferBytes)
	}
	return decoded, nil
}

// buildUploadScript 生成「创建父目录 + base64 解码落盘 + 设置权限」的脚本。
func buildUploadScript(remotePath string, content []byte, mode string) string {
	dir := ""
	if idx := strings.LastIndex(remotePath, "/"); idx > 0 {
		dir = remotePath[:idx]
	}
	encoded := base64.StdEncoding.EncodeToString(content)
	mkdir := ""
	if dir != "" {
		mkdir = "mkdir -p " + shellQuote(dir) + " && "
	}
	return fmt.Sprintf("%sprintf '%%s' '%s' | base64 -d > %s && chmod %s %s",
		mkdir, encoded, shellQuote(remotePath), shellQuote(mode), shellQuote(remotePath))
}

// shellQuote 用单引号包裹，内部单引号按 POSIX 规则转义。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func stripWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
