package threatintel

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// unzipFirstCSV 从 zip 字节里取出第一个 .csv 文件的内容。
// abuse.ch 的导出是单文件压缩包，但格式变化时别把整包当 CSV 解析。
func unzipFirstCSV(body []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("解压失败: %w", err)
	}
	// 解压后大小上限：压缩比可以被做到极高，一个 32MB 的 zip 能解出几 GB，
	// 不设限就是给自己留一个内存打爆的口子。
	const maxUncompressed = 128 << 20
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
			continue
		}
		if f.UncompressedSize64 > maxUncompressed {
			return nil, fmt.Errorf("压缩包内 %s 解压后 %d 字节，超过上限 %d", f.Name, f.UncompressedSize64, maxUncompressed)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("打开压缩包内文件失败: %w", err)
		}
		defer rc.Close()
		data, err := io.ReadAll(io.LimitReader(rc, maxUncompressed))
		if err != nil {
			return nil, fmt.Errorf("读取压缩包内文件失败: %w", err)
		}
		return data, nil
	}
	return nil, fmt.Errorf("压缩包里没有 .csv 文件")
}

// csvHeaderIndex 把表头映射成 列名->下标，全部小写。
// abuse.ch 的导出版本间会调整列顺序甚至列名，所以解析一律按表头取名，
// 不按位置硬编码：位置一换就会把 URL 当日期存进去。
func csvHeaderIndex(header []string) map[string]int {
	idx := make(map[string]int, len(header))
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return idx
}

// pick 按候选列名依次取第一个命中的列值，找不到返回空串。
func pick(record []string, idx map[string]int, names ...string) string {
	for _, name := range names {
		if i, ok := idx[name]; ok && i >= 0 && i < len(record) {
			return strings.TrimSpace(record[i])
		}
	}
	return ""
}

// parseCSVRecords 跳过 # 注释行后解析 CSV。abuse.ch 的导出常在正文前带注释块。
func parseCSVRecords(body []byte) ([][]string, error) {
	// 逐行剔除注释，再交给 csv.Reader，避免 csv 把 "; ..." 当数据列。
	var buf bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 CSV 失败: %w", err)
	}
	r := csv.NewReader(&buf)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("解析 CSV 失败: %w", err)
	}
	return records, nil
}

// confidenceFrom 把 abuse.ch 的 confidence_level（0-100）夹到合法区间，
// 缺省时用给定默认值。
func confidenceFrom(raw string, def int) int {
	if raw == "" {
		return def
	}
	n := 0
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
		if n > 1000 {
			return def
		}
	}
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}
