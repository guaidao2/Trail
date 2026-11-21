package database

import "testing"

// 态势图聚合：主机节点、发现计数、IOC 边、事件与统计都要对得上。
func TestWallGraphAggregates(t *testing.T) {
	db := newHostTestDB(t)

	web, err := db.CreateHost(&Host{Name: "web-01", Address: "10.0.0.11", Protocol: "ssh", AuthType: "password", GroupName: "prod"})
	if err != nil {
		t.Fatalf("CreateHost web: %v", err)
	}
	dbHost, err := db.CreateHost(&Host{Name: "db-01", Address: "10.0.0.12", Protocol: "ssh", AuthType: "password", GroupName: "prod"})
	if err != nil {
		t.Fatalf("CreateHost db: %v", err)
	}

	// web-01：一条 critical + 一条 high；db-01：一条 medium
	for _, f := range []FindingUpsert{
		{HostID: web.ID, Source: "log_scan", Kind: "log", RuleID: "r-critical", Title: "webshell 落地", Category: "web", Severity: "critical", Subject: "1.2.3.4", Evidence: "ev1"},
		{HostID: web.ID, Source: "log_scan", Kind: "log", RuleID: "r-high", Title: "SSH 爆破", Category: "auth", Severity: "high", Subject: "1.2.3.5", Evidence: "ev2"},
		{HostID: dbHost.ID, Source: "baseline_audit", Kind: "baseline", RuleID: "r-medium", Title: "内核参数不合规", Category: "baseline", Severity: "medium", Subject: "/proc/sys", Evidence: "ev3"},
	} {
		if _, err := db.UpsertFinding(f); err != nil {
			t.Fatalf("UpsertFinding: %v", err)
		}
	}

	ioc, _, err := db.UpsertIOC(IOCUpsert{Type: "ip", Value: "203.0.113.9", Severity: "high", Source: "log_scan"})
	if err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}
	if err := db.RecordIOCHit(ioc.ID, web.ID, "log_scan", "r-critical", "evidence"); err != nil {
		t.Fatalf("RecordIOCHit: %v", err)
	}

	graph, err := db.WallGraph(RBACListAccess{Scope: RBACScopeAll}, 30, true)
	if err != nil {
		t.Fatalf("WallGraph: %v", err)
	}

	if graph.Stats.Hosts != 2 {
		t.Fatalf("主机数应为 2，实际 %d", graph.Stats.Hosts)
	}
	if graph.Stats.FindingsOpen != 3 {
		t.Fatalf("待处置发现应为 3，实际 %d", graph.Stats.FindingsOpen)
	}
	// web-01 的最高严重度是 critical，所以它那两条都算高危待处置
	if graph.Stats.FindingsHigh != 2 {
		t.Fatalf("高危待处置应为 2，实际 %d", graph.Stats.FindingsHigh)
	}
	if graph.Stats.IOCTotal != 1 {
		t.Fatalf("IOC 总数应为 1，实际 %d", graph.Stats.IOCTotal)
	}

	// 节点：两台主机 + 一个 IOC
	var hostNode, iocNode *WallNode
	for i := range graph.Nodes {
		switch graph.Nodes[i].ID {
		case "host:" + web.ID:
			hostNode = &graph.Nodes[i]
		case "ioc:" + ioc.ID:
			iocNode = &graph.Nodes[i]
		}
	}
	if hostNode == nil || iocNode == nil {
		t.Fatalf("节点缺失：host=%v ioc=%v", hostNode, iocNode)
	}
	if hostNode.Findings != 2 || hostNode.Severity != "critical" {
		t.Fatalf("web-01 节点聚合不对: %+v", *hostNode)
	}
	if hostNode.IOCHits < 1 {
		t.Fatalf("web-01 应有 IOC 命中，实际 %d", hostNode.IOCHits)
	}
	if hostNode.Risk == 0 || hostNode.Health >= 1 {
		t.Fatalf("有风险的主机风险分应大于 0 且健康度小于 1: %+v", *hostNode)
	}

	if len(graph.Edges) != 1 {
		t.Fatalf("应有 1 条 IOC→主机 边，实际 %d: %+v", len(graph.Edges), graph.Edges)
	}
	if e := graph.Edges[0]; e.Source != "ioc:"+ioc.ID || e.Target != "host:"+web.ID {
		t.Fatalf("边方向不对: %+v", e)
	}

	if len(graph.Events) == 0 {
		t.Fatal("应有事件（发现或 IOC 命中）")
	}
	if graph.GeneratedAt == "" {
		t.Fatal("generated_at 不应为空")
	}
}

// 空库也要返回结构完整的结果，而不是 nil（前端不做空值分支）。
func TestWallGraphEmpty(t *testing.T) {
	db := newHostTestDB(t)
	graph, err := db.WallGraph(RBACListAccess{Scope: RBACScopeAll}, 0, true)
	if err != nil {
		t.Fatalf("WallGraph: %v", err)
	}
	if graph == nil || graph.Nodes == nil || graph.Edges == nil || graph.Events == nil {
		t.Fatalf("空库应返回空切片而非 nil: %+v", graph)
	}
	if graph.Stats.Hosts != 0 {
		t.Fatalf("空库主机数应为 0，实际 %d", graph.Stats.Hosts)
	}
}

// 权限边界：scope=own 的用户只能看到自己的主机，事件也不能泄露别人的发现；
// 无权读 IOC（includeIOC=false）时不应出现 IOC 节点、边与统计。
func TestWallGraphRespectsScopeAndIOCPermission(t *testing.T) {
	db := newHostTestDB(t)

	mine, err := db.CreateHost(&Host{Name: "mine", Address: "10.0.0.21", Protocol: "ssh", AuthType: "password", OwnerID: "u1"})
	if err != nil {
		t.Fatalf("CreateHost mine: %v", err)
	}
	other, err := db.CreateHost(&Host{Name: "other", Address: "10.0.0.22", Protocol: "ssh", AuthType: "password", OwnerID: "u2"})
	if err != nil {
		t.Fatalf("CreateHost other: %v", err)
	}
	for _, f := range []FindingUpsert{
		{HostID: mine.ID, Source: "log_scan", Kind: "log", RuleID: "r1", Title: "我的告警", Category: "web", Severity: "high", Subject: "a", Evidence: "e"},
		{HostID: other.ID, Source: "log_scan", Kind: "log", RuleID: "r2", Title: "别人的告警", Category: "web", Severity: "critical", Subject: "b", Evidence: "e"},
	} {
		if _, err := db.UpsertFinding(f); err != nil {
			t.Fatalf("UpsertFinding: %v", err)
		}
	}
	ioc, _, err := db.UpsertIOC(IOCUpsert{Type: "ip", Value: "203.0.113.77", Severity: "high", Source: "log_scan"})
	if err != nil {
		t.Fatalf("UpsertIOC: %v", err)
	}
	if err := db.RecordIOCHit(ioc.ID, other.ID, "log_scan", "r2", "e"); err != nil {
		t.Fatalf("RecordIOCHit: %v", err)
	}

	graph, err := db.WallGraph(RBACListAccess{UserID: "u1", Scope: RBACScopeOwn}, 30, true)
	if err != nil {
		t.Fatalf("WallGraph: %v", err)
	}
	if graph.Stats.Hosts != 1 {
		t.Fatalf("own 作用域只应看到 1 台主机，实际 %d", graph.Stats.Hosts)
	}
	for _, n := range graph.Nodes {
		if n.ID == "host:"+other.ID {
			t.Fatalf("不应出现别人的主机节点: %+v", n)
		}
	}
	if len(graph.Edges) != 0 {
		t.Fatalf("别人的主机上的 IOC 命中不应作为边出现: %+v", graph.Edges)
	}
	for _, e := range graph.Events {
		if e.Title == "别人的告警" || e.Host == "other" || e.Host == other.ID {
			t.Fatalf("事件泄露了无权限主机的数据: %+v", e)
		}
	}

	// 无 ioc:read：IOC 节点/边/统计都要为空
	graph2, err := db.WallGraph(RBACListAccess{Scope: RBACScopeAll}, 30, false)
	if err != nil {
		t.Fatalf("WallGraph(no ioc): %v", err)
	}
	for _, n := range graph2.Nodes {
		if n.Kind == "ioc" {
			t.Fatalf("无权读 IOC 时不应出现 IOC 节点: %+v", n)
		}
	}
	if len(graph2.Edges) != 0 {
		t.Fatalf("无权读 IOC 时不应有边: %+v", graph2.Edges)
	}
	if graph2.Stats.IOCTotal != 0 || graph2.Stats.IOCObserved != 0 {
		t.Fatalf("无权读 IOC 时统计应为 0: %+v", graph2.Stats)
	}
	// IOC 事件同样不能泄露（跑马灯里出现过 IOC 值就是越权）。
	for _, e := range graph2.Events {
		if e.Kind == "ioc" || e.Title == "203.0.113.77" {
			t.Fatalf("无权读 IOC 时不应出现 IOC 事件: %+v", e)
		}
	}
}
