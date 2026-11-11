package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trail/internal/database"
	"trail/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// setupConversationRBACTest 建一个带单个操作员的测试库（原先定义在被删除的
// conversation_rbac_test.go 里，rbac_boundary_test.go 仍在使用）。
func setupConversationRBACTest(t *testing.T) (*database.DB, *database.RBACUser) {
	t.Helper()
	db, err := database.NewDB(filepath.Join(t.TempDir(), "conversation-rbac.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateRBACUser("operator1", "Operator One", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser: %v", err)
	}
	return db, user
}

// performConversationRequest 以给定用户身份直接调用 gin handler，返回响应记录器。
func performConversationRequest(user *database.RBACUser, method, path string, body map[string]string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, path, bytes.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set(security.ContextSessionKey, security.Session{
		UserID:      user.ID,
		Username:    user.Username,
		Permissions: map[string]bool{"chat:write": true},
		Scope:       database.RBACScopeAssigned,
	})
	handler(c)
	return w
}
