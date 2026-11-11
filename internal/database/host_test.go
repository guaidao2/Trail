package database

import (
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func newHostTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "hosts.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestHostCRUDAndProbe(t *testing.T) {
	db := newHostTestDB(t)

	created, err := db.CreateHost(&Host{
		Name:         "web-01",
		Address:      "10.0.0.11",
		Protocol:     "ssh",
		Username:     "root",
		AuthType:     "password",
		SecretCipher: "cipher-blob",
		GroupName:    "web",
		Env:          "prod",
		Tags:         "nginx,api",
		Remark:       "primary web node",
	})
	if err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	if created.ID == "" || created.Port != 22 {
		t.Fatalf("created host = %#v, want generated id and default ssh port", created)
	}
	if !created.HasSecret {
		t.Fatal("HasSecret should be true when a cipher is stored")
	}
	if created.Status != "unknown" {
		t.Fatalf("status = %q, want unknown", created.Status)
	}

	// 凭据密文保留，但更新时不回填明文即可保持原值
	updated, err := db.UpdateHost(&Host{ID: created.ID, Name: "web-01-renamed", Address: "10.0.0.12", Port: 2222})
	if err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}
	if updated.Name != "web-01-renamed" || updated.Address != "10.0.0.12" || updated.Port != 2222 {
		t.Fatalf("updated host = %#v", updated)
	}
	if updated.SecretCipher != "cipher-blob" {
		t.Fatalf("secret cipher should be preserved, got %q", updated.SecretCipher)
	}

	if err := db.UpdateHostProbe(created.ID, "online", "", "Linux 6.1"); err != nil {
		t.Fatalf("UpdateHostProbe: %v", err)
	}
	probed, err := db.GetHost(created.ID)
	if err != nil || probed == nil {
		t.Fatalf("GetHost after probe: %v, %v", probed, err)
	}
	if probed.Status != "online" || probed.OSInfo != "Linux 6.1" || probed.LastCheck == "" {
		t.Fatalf("probe result not stored: %#v", probed)
	}

	if err := db.DeleteHost(created.ID); err != nil {
		t.Fatalf("DeleteHost: %v", err)
	}
	if gone, err := db.GetHost(created.ID); err != nil || gone != nil {
		t.Fatalf("host should be gone: %#v, %v", gone, err)
	}
	if err := db.DeleteHost(created.ID); err == nil {
		t.Fatal("deleting a missing host should fail")
	}
}

func TestCreateHostValidation(t *testing.T) {
	db := newHostTestDB(t)

	if _, err := db.CreateHost(&Host{Address: "  "}); err == nil {
		t.Fatal("empty address must be rejected")
	}
	if _, err := db.CreateHost(&Host{Address: "10.0.0.1", Protocol: "rdp"}); err == nil {
		t.Fatal("unsupported protocol must be rejected")
	}
	if _, err := db.CreateHost(&Host{Address: "10.0.0.1", AuthType: "kerberos"}); err == nil {
		t.Fatal("unsupported auth type must be rejected")
	}

	telnet, err := db.CreateHost(&Host{Address: "10.0.0.2", Protocol: "telnet"})
	if err != nil {
		t.Fatalf("CreateHost telnet: %v", err)
	}
	if telnet.Port != 23 {
		t.Fatalf("telnet default port = %d, want 23", telnet.Port)
	}
}

func TestListHostsRespectsOwnershipScope(t *testing.T) {
	db := newHostTestDB(t)

	// 归属授权要求被授权用户真实存在（rbac_users），夹具里必须先建出来，并使用生成的 ID。
	u1, err := db.CreateRBACUser("u1", "User One", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser u1: %v", err)
	}
	u2, err := db.CreateRBACUser("u2", "User Two", "hash", true, nil)
	if err != nil {
		t.Fatalf("CreateRBACUser u2: %v", err)
	}

	mine, err := db.CreateHost(&Host{Address: "10.0.0.21", OwnerID: u1.ID})
	if err != nil {
		t.Fatalf("CreateHost mine: %v", err)
	}
	theirs, err := db.CreateHost(&Host{Address: "10.0.0.22", OwnerID: u2.ID})
	if err != nil {
		t.Fatalf("CreateHost theirs: %v", err)
	}
	if _, err := db.CreateHost(&Host{Address: "10.0.0.23"}); err != nil {
		t.Fatalf("CreateHost unowned: %v", err)
	}

	list, total, err := db.ListHosts(50, 0, HostFilter{}, RBACListAccess{UserID: u1.ID, Scope: RBACScopeOwn})
	if err != nil {
		t.Fatalf("ListHosts own: %v", err)
	}
	if total != 1 || len(list) != 1 || list[0].ID != mine.ID {
		t.Fatalf("own scope list = %#v (total %d), want only %s", list, total, mine.ID)
	}

	list, total, err = db.ListHosts(50, 0, HostFilter{}, RBACListAccess{UserID: u1.ID, Scope: RBACScopeAll})
	if err != nil {
		t.Fatalf("ListHosts all: %v", err)
	}
	if total != 3 || len(list) != 3 {
		t.Fatalf("all scope list total = %d, want 3", total)
	}

	if err := db.AssignResourceToUser(u1.ID, "host", theirs.ID); err != nil {
		t.Fatalf("AssignResourceToUser: %v", err)
	}
	list, total, err = db.ListHosts(50, 0, HostFilter{}, RBACListAccess{UserID: u1.ID, Scope: RBACScopeAssigned})
	if err != nil {
		t.Fatalf("ListHosts assigned: %v", err)
	}
	if total != 2 {
		t.Fatalf("assigned scope total = %d, want 2 (owned + assigned)", total)
	}
}

func TestListHostsFilters(t *testing.T) {
	db := newHostTestDB(t)
	if _, err := db.CreateHost(&Host{Name: "db-01", Address: "10.1.0.1", GroupName: "db", Env: "prod", Tags: "mysql"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateHost(&Host{Name: "db-02", Address: "10.1.0.2", GroupName: "db", Env: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateHost(&Host{Name: "web-01", Address: "10.1.0.3", GroupName: "web", Env: "prod"}); err != nil {
		t.Fatal(err)
	}

	all := RBACListAccess{Scope: RBACScopeAll}
	if _, total, err := db.ListHosts(50, 0, HostFilter{Keyword: "db-"}, all); err != nil || total != 2 {
		t.Fatalf("keyword filter total = %d, %v", total, err)
	}
	if _, total, err := db.ListHosts(50, 0, HostFilter{Group: "web"}, all); err != nil || total != 1 {
		t.Fatalf("group filter total = %d, %v", total, err)
	}
	if _, total, err := db.ListHosts(50, 0, HostFilter{Environment: "prod"}, all); err != nil || total != 2 {
		t.Fatalf("environment filter total = %d, %v", total, err)
	}
	if _, total, err := db.ListHosts(50, 0, HostFilter{Keyword: "mysql"}, all); err != nil || total != 1 {
		t.Fatalf("tags filter total = %d, %v", total, err)
	}
}
