package database

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// 攻防态势图（AWD 风格沙盘）的数据契约。
//
//	节点：主机（kind=host）与 IOC（kind=ioc）
//	边  ：IOC 命中主机（ioc_host_hit），带状态与命中次数
//	事件：最近发现与 IOC 命中，供底部滚动条
//
// 这是**展示层**数据：只读聚合，不引入新的业务概念。
// 权限沿用 host:read 的作用域——看不到的主机不会出现在图里。

// WallNode 是图上的一个节点。
type WallNode struct {
	ID       string  `json:"id"`
	Kind     string  `json:"kind"` // host | ioc
	Name     string  `json:"name,omitempty"`
	IP       string  `json:"ip,omitempty"`
	Group    string  `json:"group,omitempty"`
	Status   string  `json:"status,omitempty"`
	Severity string  `json:"severity,omitempty"`
	Findings int     `json:"findings_open"`
	IOCHits  int     `json:"ioc_hits"`
	Health   float64 `json:"health"`     // 0..1，1 为健康
	Risk     int     `json:"risk_score"` // 0..100
	LastSeen string  `json:"last_seen,omitempty"`
	IOCType  string  `json:"ioc_type,omitempty"`
	Value    string  `json:"value,omitempty"`
}

// WallEdge 是 IOC → 主机的命中关系。
type WallEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"` // ioc:<id>
	Target   string `json:"target"` // host:<id>
	Value    string `json:"value,omitempty"`
	IOCType  string `json:"ioc_type,omitempty"`
	Status   string `json:"status,omitempty"` // observed | confirmed | blocked
	Severity string `json:"severity,omitempty"`
	Hits     int    `json:"hits"`
	LastSeen string `json:"last_seen,omitempty"`
}

// WallStats 是大屏左上角的几个大数字。
type WallStats struct {
	Hosts          int `json:"hosts"`
	HostsReachable int `json:"hosts_reachable"`
	FindingsOpen   int `json:"findings_open"`
	FindingsHigh   int `json:"findings_high"`
	KEVHits        int `json:"kev_hits"`
	IOCTotal       int `json:"ioc_total"`
	IOCObserved    int `json:"ioc_observed"`
	IOCConfirmed   int `json:"ioc_confirmed"`
	IOCBlocked     int `json:"ioc_blocked"`
}

// WallEvent 是底部滚动条的一条事件。
type WallEvent struct {
	TS       string `json:"ts"`
	Kind     string `json:"kind"` // finding | ioc
	Host     string `json:"host"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Status   string `json:"status,omitempty"`
}

// WallGraph 是一次聚合结果。
type WallGraph struct {
	GeneratedAt string      `json:"generated_at"`
	Stats       WallStats   `json:"stats"`
	Nodes       []WallNode  `json:"nodes"`
	Edges       []WallEdge  `json:"edges"`
	Events      []WallEvent `json:"events"`
}

// wallHostFilter 拼出"只看这些主机"的 SQL 片段；空集合时返回恒假条件，
// 这样 LIMIT 作用在可见行上，而不是先截全平台再丢弃。
func wallHostFilter(column string, ids []string) (string, []interface{}) {
	if len(ids) == 0 {
		return " AND 1=0", nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	return " AND " + column + " IN (" + ph + ")", args
}

var wallSeverityRank = map[string]int{
	"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
}

func wallWorse(a, b string) string {
	if wallSeverityRank[strings.ToLower(a)] >= wallSeverityRank[strings.ToLower(b)] {
		return strings.ToLower(a)
	}
	return strings.ToLower(b)
}

// WallGraph 聚合态势图数据。eventLimit 控制底部事件条数（默认 30）。
func (db *DB) WallGraph(access RBACListAccess, eventLimit int, includeIOC bool) (*WallGraph, error) {
	if eventLimit <= 0 || eventLimit > 200 {
		eventLimit = 30
	}
	hosts, _, err := db.ListHosts(500, 0, HostFilter{}, access)
	if err != nil {
		return nil, fmt.Errorf("读取主机失败: %w", err)
	}

	graph := &WallGraph{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Nodes:       []WallNode{},
		Edges:       []WallEdge{},
		Events:      []WallEvent{},
	}
	hostByID := map[string]*Host{}
	hostName := func(id string) string {
		if h, ok := hostByID[id]; ok && h.Name != "" {
			return h.Name
		}
		return id
	}

	// 主机节点：先占位，随后被发现与 IOC 命中补齐。
	for _, h := range hosts {
		hostByID[h.ID] = h
		graph.Nodes = append(graph.Nodes, WallNode{
			ID:     "host:" + h.ID,
			Kind:   "host",
			Name:   h.Name,
			IP:     h.Address,
			Group:  h.GroupName,
			Status: h.Status,
		})
		graph.Stats.Hosts++
		if strings.EqualFold(h.Status, "online") || strings.EqualFold(h.Status, "ok") || strings.EqualFold(h.Status, "reachable") {
			graph.Stats.HostsReachable++
		}
	}
	nodeIdx := make(map[string]int, len(graph.Nodes))
	for i, n := range graph.Nodes {
		nodeIdx[n.ID] = i
	}

	// 可见主机 ID：事件与统计都要按它收口，LIMIT 才能作用在“你看得到的行”上，
	// 而不是先截全平台再丢弃（否则 scope=own 的用户拿到的跑马灯几乎总是空的）。
	visibleIDs := make([]string, 0, len(hosts))
	for _, h := range hosts {
		visibleIDs = append(visibleIDs, h.ID)
	}
	findingHostFilter, findingHostArgs := wallHostFilter("host_id", visibleIDs)
	kevHostFilter, kevHostArgs := wallHostFilter("f.host_id", visibleIDs)
	iocHostFilter, iocHostArgs := wallHostFilter("h.host_id", visibleIDs)

	// 发现聚合：按主机统计 open 数与最高严重度。
	rows, err := db.Query(`SELECT host_id,
		SUM(CASE WHEN status IN ('open','acked') THEN 1 ELSE 0 END),
		COALESCE(MAX(CASE WHEN status IN ('open','acked') THEN CASE severity
			WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
			WHEN 'low' THEN 2 ELSE 1 END END), 0)
		FROM detect_findings GROUP BY host_id`)
	if err != nil {
		return nil, fmt.Errorf("统计检测发现失败: %w", err)
	}
	rankToSeverity := []string{"", "info", "low", "medium", "high", "critical"}
	for rows.Next() {
		var hostID string
		var open, maxRank int
		if err := rows.Scan(&hostID, &open, &maxRank); err != nil {
			rows.Close()
			return nil, err
		}
		idx, ok := nodeIdx["host:"+hostID]
		if !ok {
			continue
		}
		graph.Nodes[idx].Findings = open
		if maxRank > 0 && maxRank < len(rankToSeverity) {
			graph.Nodes[idx].Severity = wallWorse(graph.Nodes[idx].Severity, rankToSeverity[maxRank])
		}
		graph.Stats.FindingsOpen += open
		if maxRank >= 4 {
			graph.Stats.FindingsHigh += open
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// IOC 命中边：IOC → 主机。IOC 详情属于 ioc:read 的范围，无权时整段跳过。
	if includeIOC {
		rows, err = db.Query(`SELECT h.id, h.ioc_id, h.host_id, h.hit_count,
		COALESCE(CAST(h.last_seen AS TEXT), ''),
		i.value, i.ioc_type, i.status, i.severity
		FROM ioc_host_hit h JOIN ioc i ON i.id = h.ioc_id`)
		if err != nil {
			return nil, fmt.Errorf("统计 IOC 命中失败: %w", err)
		}
		iocSeen := map[string]int{}
		for rows.Next() {
			var hitID, iocID, hostID, lastSeen, value, iocType, status, severity string
			var hits int
			if err := rows.Scan(&hitID, &iocID, &hostID, &hits, &lastSeen, &value, &iocType, &status, &severity); err != nil {
				rows.Close()
				return nil, err
			}
			hostIdx, ok := nodeIdx["host:"+hostID]
			if !ok {
				continue // 无权查看该主机
			}
			graph.Edges = append(graph.Edges, WallEdge{
				ID: "hit:" + hitID, Source: "ioc:" + iocID, Target: "host:" + hostID,
				Value: value, IOCType: iocType, Status: strings.ToLower(status),
				Severity: strings.ToLower(severity), Hits: hits, LastSeen: lastSeen,
			})
			graph.Nodes[hostIdx].IOCHits += hits
			if idx, ok := iocSeen[iocID]; ok {
				graph.Nodes[idx].IOCHits += hits
				if lastSeen > graph.Nodes[idx].LastSeen {
					graph.Nodes[idx].LastSeen = lastSeen
				}
				continue
			}
			iocSeen[iocID] = len(graph.Nodes)
			graph.Nodes = append(graph.Nodes, WallNode{
				ID: "ioc:" + iocID, Kind: "ioc", Name: value, Value: value,
				IOCType: iocType, Status: strings.ToLower(status), Severity: strings.ToLower(severity),
				IOCHits: hits, LastSeen: lastSeen,
			})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}

	// 风险评分与健康度：发现数 + IOC 命中，严重度加权。
	for i := range graph.Nodes {
		n := &graph.Nodes[i]
		if n.Kind != "host" {
			continue
		}
		weight := wallSeverityRank[strings.ToLower(n.Severity)]
		if weight == 0 {
			weight = 1
		}
		score := n.Findings*3*weight + n.IOCHits*8
		if score > 100 {
			score = 100
		}
		n.Risk = score
		n.Health = 1 - float64(score)/100
		if n.Severity == "" {
			n.Severity = "info"
		}
	}

	// 情报库 KEV 命中（本环境资产上命中在野利用漏洞的条数）。
	if err := db.QueryRow(`SELECT COUNT(*) FROM detect_findings f
		JOIN vuln_intel v ON v.cve_id = f.rule_id
		WHERE v.kev = 1 AND f.status IN ('open','acked') AND f.source = 'vuln_intel'`+kevHostFilter,
		kevHostArgs...).Scan(&graph.Stats.KEVHits); err != nil {
		graph.Stats.KEVHits = 0
	}

	// IOC 状态分布（无权读 IOC 时保持 0）。
	if includeIOC {
		if err := db.QueryRow(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN status='observed' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='confirmed' THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END),0)
		FROM ioc`).Scan(&graph.Stats.IOCTotal, &graph.Stats.IOCObserved,
			&graph.Stats.IOCConfirmed, &graph.Stats.IOCBlocked); err != nil {
			graph.Stats.IOCTotal, graph.Stats.IOCObserved = 0, 0
			graph.Stats.IOCConfirmed, graph.Stats.IOCBlocked = 0, 0
		}
	}

	// 最近事件：发现与 IOC 命中各取一部分，合并后按时间倒序。
	findingArgs := append(append([]interface{}{}, findingHostArgs...), eventLimit)
	rows, err = db.Query(`SELECT COALESCE(CAST(last_seen AS TEXT),''), host_id, severity, title, status
		FROM detect_findings WHERE 1=1`+findingHostFilter+` ORDER BY last_seen DESC LIMIT ?`, findingArgs...)
	if err != nil {
		return nil, fmt.Errorf("读取最近发现失败: %w", err)
	}
	for rows.Next() {
		var ts, hostID, severity, title, status string
		if err := rows.Scan(&ts, &hostID, &severity, &title, &status); err != nil {
			rows.Close()
			return nil, err
		}
		// 只保留可见主机的事件：否则 scope=own 的用户会看到全平台发现标题。
		if _, ok := hostByID[hostID]; !ok {
			continue
		}
		graph.Events = append(graph.Events, WallEvent{
			TS: ts, Kind: "finding", Host: hostName(hostID),
			Severity: strings.ToLower(severity), Title: title, Status: status,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// IOC 事件与 IOC 节点口径一致：无 ioc:read 时整段不查，避免在跑马灯里泄露 IOC 值。
	if includeIOC {
		iocArgs := append(append([]interface{}{}, iocHostArgs...), eventLimit)
		rows, err = db.Query(`SELECT COALESCE(CAST(h.last_seen AS TEXT),''), h.host_id, i.value, i.severity, i.status
		FROM ioc_host_hit h JOIN ioc i ON i.id = h.ioc_id
		WHERE 1=1`+iocHostFilter+` ORDER BY h.last_seen DESC LIMIT ?`, iocArgs...)
		if err != nil {
			return nil, fmt.Errorf("读取最近 IOC 命中失败: %w", err)
		}
		for rows.Next() {
			var ts, hostID, value, severity, status string
			if err := rows.Scan(&ts, &hostID, &value, &severity, &status); err != nil {
				rows.Close()
				return nil, err
			}
			if _, ok := hostByID[hostID]; !ok {
				continue
			}
			graph.Events = append(graph.Events, WallEvent{
				TS: ts, Kind: "ioc", Host: hostName(hostID),
				Severity: strings.ToLower(severity), Title: value, Status: status,
			})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}

	sort.SliceStable(graph.Events, func(i, j int) bool {
		return graph.Events[i].TS > graph.Events[j].TS
	})
	if len(graph.Events) > eventLimit {
		graph.Events = graph.Events[:eventLimit]
	}
	return graph, nil
}
