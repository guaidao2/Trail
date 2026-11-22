//go:build cgo

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"trail/internal/database"
	"trail/internal/security"
	"trail/internal/threatintel"
)

func newThreatIntelTestHandler(t *testing.T) (*ThreatIntelHandler, *database.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "threat-handler.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("建库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	svc := threatintel.NewService(db, threatintel.Config{Timeout: 5 * time.Second}, zap.NewNop())
	if err := svc.EnsureSources(httptest.NewRequest(http.MethodGet, "/", nil).Context()); err != nil {
		t.Fatalf("注册源失败: %v", err)
	}
	return NewThreatIntelHandler(db, func() *threatintel.Service { return svc }, zap.NewNop()), db
}

func doThreatRequest(t *testing.T, h gin.HandlerFunc, target string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, target, nil)
	h(c)
	var body map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w, body
}

func TestThreatIntelListSourcesHandler(t *testing.T) {
	h, _ := newThreatIntelTestHandler(t)
	w, body := doThreatRequest(t, h.ListSources, "/api/threat-intel/sources")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d，body=%s", w.Code, w.Body.String())
	}
	if body["enabled"] != true {
		t.Errorf("模块应报告已启用")
	}
	items, _ := body["items"].([]interface{})
	if len(items) == 0 {
		t.Fatal("应至少注册了 internetdb 一个源")
	}
	// 源清单按 mode+name 排序，feed 会排在 lookup 前面，所以不能断言下标，
	// 只能确认 internetdb 在里面且不要求 key。
	var found map[string]interface{}
	for _, raw := range items {
		item, _ := raw.(map[string]interface{})
		if item["source"] == "internetdb" {
			found = item
		}
	}
	if found == nil {
		t.Fatalf("源清单里找不到 internetdb")
	}
	if found["requires_key"] != false {
		t.Errorf("internetdb 不应要求 key")
	}
	if found["mode"] != "lookup" {
		t.Errorf("internetdb 应为 lookup 模式，实际 %v", found["mode"])
	}
}

func TestThreatIntelQueryHandlerValidation(t *testing.T) {
	h, _ := newThreatIntelTestHandler(t)

	// 缺 value 应 400，而不是去打网络。
	w, _ := doThreatRequest(t, h.Query, "/api/threat-intel/query?type=ip")
	if w.Code != http.StatusBadRequest {
		t.Errorf("空 value 应返回 400，实际 %d", w.Code)
	}

	// 私网地址应 200 且明确说明跳过，不发外部请求。
	w, body := doThreatRequest(t, h.Query, "/api/threat-intel/query?type=ip&value=192.168.1.10")
	if w.Code != http.StatusOK {
		t.Fatalf("私网查询应 200，实际 %d body=%s", w.Code, w.Body.String())
	}
	note, _ := body["note"].(string)
	if note == "" {
		t.Error("私网查询应给出说明")
	}
	if results, _ := body["results"].([]interface{}); len(results) != 0 {
		t.Errorf("私网地址不应有外部结果，实际 %d 条", len(results))
	}
}

func TestThreatIntelListFeedHandler(t *testing.T) {
	h, db := newThreatIntelTestHandler(t)

	if _, err := db.UpsertThreatIntelFeed([]database.ThreatIntelFeedEntry{
		{Source: "feodo", IndicatorType: "ip", Normalized: "203.0.113.7", Category: "c2", Malware: "Emotet"},
		{Source: "urlhaus", IndicatorType: "url", Normalized: "http://evil.example/x", Category: "malware_url"},
	}); err != nil {
		t.Fatalf("写入订阅条目失败: %v", err)
	}

	w, body := doThreatRequest(t, h.ListFeed, "/api/threat-intel/feed?page=1&page_size=10")
	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d body=%s", w.Code, w.Body.String())
	}
	if total, _ := body["total"].(float64); total != 2 {
		t.Errorf("总数应为 2，实际 %v", body["total"])
	}

	w, body = doThreatRequest(t, h.ListFeed, "/api/threat-intel/feed?source=feodo")
	if w.Code != http.StatusOK {
		t.Fatalf("按源筛选状态码 %d", w.Code)
	}
	if total, _ := body["total"].(float64); total != 1 {
		t.Errorf("按源筛选总数应为 1，实际 %v", body["total"])
	}

	// type=hash 是聚合选项：入库保留 md5/sha1/sha256，筛选时展开成三者。
	if _, err := db.UpsertThreatIntelFeed([]database.ThreatIntelFeedEntry{
		{Source: "threatfox", IndicatorType: "sha256", Normalized: "abc123", Category: "payload"},
	}); err != nil {
		t.Fatalf("写入哈希条目失败: %v", err)
	}
	if _, hashBody := doThreatRequest(t, h.ListFeed, "/api/threat-intel/feed?type=hash"); hashBody["total"] == nil {
		t.Fatal("hash 筛选应返回结果体")
	} else if total, _ := hashBody["total"].(float64); total != 1 {
		t.Errorf("hash 聚合筛选应命中 1 条 sha256，实际 %v", hashBody["total"])
	}
}

// 采纳是外部证据入档，不是重新判一遍：已存在条目的置信度、严重度与人工备注
// 都不能被外部摘要覆盖，否则人工调好的评级会被冲掉。
func TestThreatIntelAdoptPreservesManualFields(t *testing.T) {
	h, db := newThreatIntelTestHandler(t)

	existing, created, err := db.UpsertIOC(database.IOCUpsert{
		Type:       "ip",
		Value:      "203.0.113.55",
		Status:     database.IOCStatusConfirmed,
		Confidence: 95,
		Severity:   "critical",
		Source:     "manual",
		Note:       "人工确认过，勿覆盖",
	})
	if err != nil || !created {
		t.Fatalf("预置 IOC 失败: %v created=%v", err, created)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body := `{"type":"ip","value":"203.0.113.55","source":"greynoise","verdict":"malicious","summary":"外部摘要"}`
	c.Request = httptest.NewRequest(http.MethodPost, "/api/threat-intel/adopt", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID:      "u1",
		Permissions: map[string]bool{"ioc:write": true, "threatintel:write": true},
	})
	h.AdoptIOC(c)

	if w.Code != http.StatusOK {
		t.Fatalf("采纳应 200，实际 %d body=%s", w.Code, w.Body.String())
	}
	after, err := db.GetIOC(existing.ID)
	if err != nil {
		t.Fatalf("读取 IOC 失败: %v", err)
	}
	if after.Confidence != 95 {
		t.Errorf("置信度被覆盖：%d", after.Confidence)
	}
	if after.Severity != "critical" {
		t.Errorf("严重度被覆盖：%s", after.Severity)
	}
	if after.Note != "人工确认过，勿覆盖" {
		t.Errorf("人工备注被覆盖：%q", after.Note)
	}
	if after.Status != database.IOCStatusConfirmed {
		t.Errorf("状态被降级：%s", after.Status)
	}
}

// 只有 threatintel:write 没有 ioc:write 的人不能借采纳动作写 IOC 表。
func TestThreatIntelAdoptRequiresIOCWrite(t *testing.T) {
	h, db := newThreatIntelTestHandler(t)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/threat-intel/adopt",
		strings.NewReader(`{"type":"ip","value":"203.0.113.77"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID:      "u2",
		Permissions: map[string]bool{"threatintel:write": true},
	})
	h.AdoptIOC(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("缺少 ioc:write 应 403，实际 %d body=%s", w.Code, w.Body.String())
	}
	if rec, _ := db.GetIOCByValue("ip", "203.0.113.77"); rec != nil {
		t.Error("被拒绝的请求不应写入 IOC")
	}
}
