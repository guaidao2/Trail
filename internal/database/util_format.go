package database

import (
	"strings"
	"time"
)

// boolToInt 把布尔值写成 SQLite 的 0/1。
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullIfEmpty 把空字符串转成 SQL NULL，避免把 "" 写进可空列。
func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// parseDBTime 兼容 go-sqlite3 读 DATETIME 的多种形态（RFC3339 带 T、空格分隔等）。
func parseDBTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
