package handler

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trail/internal/database"
	"trail/internal/security"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// 清空指纹是「主机重装换钥」后的唯一出口：没有它，所有连接都会因
// 「主机密钥不匹配」被永久拒绝。
func TestClearHostKeyEmptiesFingerprint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.NewDB(filepath.Join(t.TempDir(), "host-key.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	box, err := security.LoadSecretBox(filepath.Join(t.TempDir(), "k.key"))
	if err != nil {
		t.Fatalf("LoadSecretBox: %v", err)
	}
	cipher, err := box.Encrypt("pw")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	host, err := db.CreateHost(&database.Host{
		Name: "web-01", Address: "10.0.0.9", Protocol: "ssh", Port: 22,
		Username: "root", AuthType: "password", SecretCipher: cipher,
	})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if err := db.SetHostKey(host.ID, "SHA256:pinned"); err != nil {
		t.Fatalf("SetHostKey: %v", err)
	}

	h := NewHostHandler(db, zap.NewNop(), box)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(security.ContextSessionKey, security.Session{
			UserID:      "u1",
			Username:    "ops",
			Permissions: map[string]bool{"host:write": true},
			Scope:       database.RBACScopeAll,
		})
		c.Next()
	})
	router.DELETE("/api/hosts/:id/host-key", h.ClearHostKey)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/api/hosts/"+host.ID+"/host-key", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	updated, err := db.GetHost(host.ID)
	if err != nil || updated == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if updated.HostKey != "" {
		t.Fatalf("host_key = %q, want empty (重新信任后应由下次探测重新记录)", updated.HostKey)
	}
}
