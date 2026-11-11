package handler

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trail/internal/config"
	"trail/internal/database"
	"trail/internal/security"

	"go.uber.org/zap"
)

func TestWecomReplayGuardRequiresFreshUniqueRequest(t *testing.T) {
	h := NewRobotHandler(&config.Config{}, nil, nil, zap.NewNop())
	timestamp := time.Now().Unix()
	if !h.acceptFreshWecomRequest(fmt.Sprintf("%d", timestamp), "nonce", "signature") {
		t.Fatal("fresh request was rejected")
	}
	if h.acceptFreshWecomRequest(fmt.Sprintf("%d", timestamp), "nonce", "signature") {
		t.Fatal("duplicate request was accepted")
	}
	if h.acceptFreshWecomRequest(fmt.Sprintf("%d", timestamp-600), "old", "signature") {
		t.Fatal("stale request was accepted")
	}
}

func TestRobotServiceAccountRequiresExactSenderAllowlist(t *testing.T) {
	db, err := database.NewDB(filepath.Join(t.TempDir(), "robot-service.db"), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.BootstrapRBAC("hash", security.PermissionCatalog); err != nil {
		t.Fatal(err)
	}
	serviceUser, err := db.CreateRBACUser("robot-service-user", "Robot Service", "hash", true, []string{database.RBACSystemRoleOperator})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Robots.Lark.Auth = config.RobotAuthorizationConfig{
		Mode: config.RobotAuthModeServiceAccount, ServiceUserID: serviceUser.ID,
		AllowedExternalUsers: []string{"t:tenant|u:allowed"},
	}
	h := NewRobotHandler(cfg, db, nil, zap.NewNop())
	if got := h.HandleMessage("lark", "t:tenant|u:allowed", "列表"); strings.Contains(got, "白名单") || strings.Contains(got, "尚未绑定") {
		t.Fatalf("allowed service account sender was denied: %s", got)
	}
	if got := h.HandleMessage("lark", "t:tenant|u:denied", "列表"); !strings.Contains(got, "白名单") {
		t.Fatalf("non-allowlisted sender was not denied: %s", got)
	}
	if got := h.HandleMessage("lark", "t:tenant|u:allowed", "绑定 ABCD-1234"); !strings.Contains(got, "服务账号模式") {
		t.Fatalf("service-account robot accepted user binding: %s", got)
	}
	if got := h.HandleMessage("lark", "t:tenant|u:allowed", "whoami"); !strings.Contains(got, "Robot Service") || !strings.Contains(got, serviceUser.ID) || !strings.Contains(got, "service_account") {
		t.Fatalf("service-account identity output is incomplete: %s", got)
	}
	if got := h.HandleMessage("lark", "t:tenant|u:denied", "whoami"); !strings.Contains(got, "鉴权状态：拒绝") || strings.Contains(got, serviceUser.ID) {
		t.Fatalf("denied identity output leaked or omitted status: %s", got)
	}

	adminCfg := &config.Config{}
	adminCfg.Robots.Lark.Auth = config.RobotAuthorizationConfig{
		Mode: config.RobotAuthModeServiceAccount, ServiceUserID: "admin",
		AllowedExternalUsers: []string{"t:tenant|u:owner"},
	}
	adminHandler := NewRobotHandler(adminCfg, db, nil, zap.NewNop())
	if got := adminHandler.HandleMessage("lark", "t:tenant|u:owner", "身份"); !strings.Contains(got, "admin") || !strings.Contains(got, "鉴权状态：已授权") {
		t.Fatalf("allowlisted admin service account was denied: %s", got)
	}
}
