package vulnintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"trail/internal/database"

	"go.uber.org/zap"
)

// 用本地 httptest 覆盖整条同步链路：拉取 → 解析 → 入库 → 状态落库。
// 不依赖外网，因此既能进 CI，也能验证"源不可达时不留脏数据"。
func TestSyncerKEVAndEPSSEndToEnd(t *testing.T) {
	const kevBody = `{
	  "catalogVersion": "2026.11.21",
	  "dateReleased": "2026-11-21T00:00:00.000Z",
	  "count": 2,
	  "vulnerabilities": [
	    {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"},
	    {"cveID": "CVE-2023-38408", "dateAdded": "2023-07-19"}
	  ]
	}`
	const epssBody = `{
	  "status": "OK", "total": 2, "offset": 0, "limit": 10000,
	  "data": [
	    {"cve": "CVE-2021-44228", "epss": "0.97000", "percentile": "0.99900", "date": "2026-11-21"},
	    {"cve": "CVE-2023-38408", "epss": "0.12000", "percentile": "0.90000", "date": "2026-11-21"}
	  ]
	}`

	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(kevBody))
	})
	mux.HandleFunc("/data/v1/epss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(epssBody))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, err := database.NewDB(filepath.Join(t.TempDir(), "sync.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	off := false
	syncer := New(db, Config{
		KEVURL:      srv.URL + "/kev.json",
		EPSSBaseURL: srv.URL,
		NVDEnabled:  &off, // 本测试只覆盖 KEV + EPSS
		EPSSEnabled: true,
		MaxRuntime:  30 * time.Second,
		PageDelay:   time.Millisecond,
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sum, err := syncer.Run(ctx)
	if err != nil {
		t.Fatalf("同步失败: %v", err)
	}
	if sum.KEV != 2 {
		t.Fatalf("KEV 应标记 2 条，实际 %d", sum.KEV)
	}
	if sum.EPSS != 2 {
		t.Fatalf("EPSS 应更新 2 条，实际 %d", sum.EPSS)
	}

	// KEV 与 EPSS 都写进了同一条记录（NVD 尚未补充详情，属于桩记录）
	rec, _, _, err := db.GetVulnIntel("CVE-2021-44228")
	if err != nil || rec == nil {
		t.Fatalf("GetVulnIntel: rec=%v err=%v", rec, err)
	}
	if !rec.KEV {
		t.Fatal("KEV 全量同步后应带在野标记")
	}
	if rec.EPSS == nil || *rec.EPSS < 0.9 {
		t.Fatalf("EPSS 未写入: %+v", rec.EPSS)
	}

	// 状态：两个源都记录了最近同步时间
	for _, src := range []string{"kev", "epss"} {
		st, err := db.GetVulnIntelSync(src)
		if err != nil {
			t.Fatalf("GetVulnIntelSync(%s): %v", src, err)
		}
		if st.LastSyncAt == "" {
			t.Fatalf("%s 未记录最近同步时间", src)
		}
		if st.LastError != "" {
			t.Fatalf("%s 不应有错误: %s", src, st.LastError)
		}
	}

	// 再跑一次：KEV 是全量覆盖，清标记后重打，数量保持 2（不翻倍）
	sum2, err := syncer.Run(ctx)
	if err != nil {
		t.Fatalf("第二次同步失败: %v", err)
	}
	if sum2.KEV != 2 {
		t.Fatalf("第二次 KEV 应为 2，实际 %d", sum2.KEV)
	}
	if total, kev, _ := db.CountVulnIntel(); total != 2 || kev != 2 {
		t.Fatalf("重复同步后总数应仍为 2，实际 total=%d kev=%d", total, kev)
	}
}

// 源返回错误时必须记录到该源状态，且不影响其它源。
func TestSyncerRecordsSourceError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/data/v1/epss", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":1,"data":[{"cve":"CVE-2020-0001","epss":"0.5","percentile":"0.9","date":"2026-11-21"}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, err := database.NewDB(filepath.Join(t.TempDir(), "sync2.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	off := false
	syncer := New(db, Config{
		KEVURL: srv.URL + "/kev.json", EPSSBaseURL: srv.URL,
		NVDEnabled: &off, EPSSEnabled: true,
		MaxRuntime: 20 * time.Second, PageDelay: time.Millisecond,
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sum, err := syncer.Run(ctx)
	if err == nil {
		t.Fatal("KEV 失败时 Run 应返回错误")
	}
	if len(sum.Errors) == 0 {
		t.Fatal("Summary.Errors 应包含失败源")
	}
	// KEV 失败但 EPSS 仍然成功
	if sum.EPSS != 1 {
		t.Fatalf("EPSS 应成功写入 1 条，实际 %d", sum.EPSS)
	}
	st, _ := db.GetVulnIntelSync("kev")
	if st.LastError == "" {
		t.Fatal("KEV 源状态应记录错误")
	}
}
