package handler

import (
	"path/filepath"
	"strings"
	"testing"

	"trail/internal/config"
	"trail/internal/database"

	"go.uber.org/zap"
)

func TestHostInspectionPromptRequiresEvidenceAndHostIdentity(t *testing.T) {
	prompt := hostInspectionPrompt(&database.Host{
		ID:      "host_abc123",
		Name:    "web-01",
		Address: "10.0.0.11",
		Port:    22,
	})

	for _, want := range []string{
		"web-01", "host_abc123", "10.0.0.11:22",
		"host_probe", "host_inspect", "host_download", "host_exec",
		"证据", "已检查，无异常", "不要臆造",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("inspection prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestHostInspectionPromptFallsBackToAddress(t *testing.T) {
	prompt := hostInspectionPrompt(&database.Host{ID: "host_x", Address: "10.0.0.12", Port: 2222})
	if !strings.Contains(prompt, "10.0.0.12:2222") {
		t.Fatalf("prompt should name the host address:\n%s", prompt)
	}
	if strings.Contains(prompt, "对纳管主机 （") {
		t.Fatalf("empty name should be replaced by the address:\n%s", prompt)
	}
}

// 巡检队列必须记录 owner：子任务执行时要靠它解析运行身份，否则每个子任务都会
// 以「队列所有者不存在或已禁用」失败（曾是这样）。
func TestScheduleHostInspectionAssignsQueueOwner(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "schedule.sqlite"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	owner, err := db.CreateRBACUser("inspector", "Inspector", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}

	h := NewAgentHandler(nil, db, &config.Config{}, zap.NewNop())
	queueID, err := h.ScheduleHostInspection(&database.Host{
		ID: "host_1", Name: "web-01", Address: "10.0.0.11", Port: 22,
	}, "*/5 * * * *", owner.ID, false)
	if err != nil {
		t.Fatalf("ScheduleHostInspection: %v", err)
	}
	if got := db.GetResourceOwner("batch_task", queueID); got != owner.ID {
		t.Fatalf("queue owner = %q, want %q (否则子任务会因所有者缺失而全部失败)", got, owner.ID)
	}
}
