-- Latest SQLite structure. Update these definitions when adding tables or columns.

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    dedup_key TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 0,
    domain TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    server TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    province TEXT NOT NULL DEFAULT '',
    city TEXT NOT NULL DEFAULT '',
    responsible_person TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    business_system TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'manual',
    source_query TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'unassessed',
    tags_json TEXT NOT NULL DEFAULT '[]',
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    owner_user_id TEXT,
    last_scan_at DATETIME,
    last_scan_conversation_id TEXT NOT NULL DEFAULT '',
    last_scan_queue_id TEXT NOT NULL DEFAULT '',
    last_scan_task_id TEXT NOT NULL DEFAULT ''
);

CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    created_at DATETIME NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    category TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'admin',
    session_hint TEXT,
    client_ip TEXT,
    user_agent TEXT,
    resource_type TEXT,
    resource_id TEXT,
    message TEXT NOT NULL,
    detail_json TEXT
);

CREATE TABLE batch_task_queues (
    id TEXT PRIMARY KEY,
    title TEXT,
    role TEXT,
    agent_mode TEXT NOT NULL DEFAULT 'eino_single',
    hitl_policy TEXT NOT NULL DEFAULT '',
    schedule_mode TEXT NOT NULL DEFAULT 'manual',
    cron_expr TEXT,
    next_run_at DATETIME,
    schedule_enabled INTEGER NOT NULL DEFAULT 1,
    last_schedule_trigger_at DATETIME,
    last_schedule_error TEXT,
    last_run_error TEXT,
    concurrency INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    current_index INTEGER NOT NULL DEFAULT 0,
    owner_user_id TEXT
);

CREATE TABLE batch_tasks (
    id TEXT PRIMARY KEY,
    queue_id TEXT NOT NULL,
    message TEXT NOT NULL,
    conversation_id TEXT,
    status TEXT NOT NULL,
    started_at DATETIME,
    completed_at DATETIME,
    error TEXT,
    result TEXT,
    FOREIGN KEY (queue_id) REFERENCES batch_task_queues(id) ON DELETE CASCADE
);

CREATE TABLE chat_upload_artifacts (
    relative_path TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    role_name TEXT NOT NULL DEFAULT '默认',
    agent_mode TEXT NOT NULL DEFAULT 'eino_single',
    last_react_input TEXT,
    last_react_output TEXT,
    pinned INTEGER DEFAULT 0,
    host_id TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    owner_user_id TEXT
);

CREATE TABLE hitl_conversation_configs (
    conversation_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    mode TEXT NOT NULL DEFAULT 'off',
    sensitive_tools TEXT NOT NULL DEFAULT '[]',
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL,
    reviewer TEXT NOT NULL DEFAULT 'human'
);

CREATE TABLE hitl_interrupts (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    message_id TEXT,
    mode TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_call_id TEXT,
    payload TEXT,
    status TEXT NOT NULL,
    reviewer TEXT NOT NULL DEFAULT 'human',
    decision TEXT,
    decision_comment TEXT,
    created_at DATETIME NOT NULL,
    decided_at DATETIME,
    decided_by TEXT NOT NULL DEFAULT 'human'
);

CREATE TABLE knowledge_retrieval_logs (
    id TEXT PRIMARY KEY,
    conversation_id TEXT,
    message_id TEXT,
    query TEXT NOT NULL,
    risk_type TEXT,
    retrieved_items TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL
);

CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    mcp_execution_ids TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    reasoning_content TEXT,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE model_token_usage (
    id TEXT PRIMARY KEY,
    process_detail_id TEXT NOT NULL UNIQUE,
    message_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    orchestration TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    model_calls INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cached_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (process_detail_id) REFERENCES process_details(id) ON DELETE CASCADE,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE notification_reads_by_user (
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    read_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id, event_id)
);

CREATE TABLE process_details (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT,
    data TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE rbac_permissions (
    key TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
);

CREATE TABLE rbac_resource_assignments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
    UNIQUE(user_id, resource_type, resource_id)
);

CREATE TABLE rbac_role_permissions (
    role_id TEXT NOT NULL,
    permission_key TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (role_id, permission_key),
    FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_key) REFERENCES rbac_permissions(key) ON DELETE CASCADE
);

CREATE TABLE rbac_roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT 'assigned',
    is_system INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE rbac_user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE
);

CREATE TABLE rbac_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    is_builtin INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE robot_binding_codes (
    code_hash TEXT PRIMARY KEY,
    rbac_user_id TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (rbac_user_id) REFERENCES rbac_users(id) ON DELETE CASCADE
);

CREATE TABLE robot_user_bindings (
    id TEXT PRIMARY KEY,
    platform TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    rbac_user_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (rbac_user_id) REFERENCES rbac_users(id) ON DELETE CASCADE,
    UNIQUE(platform, external_user_id)
);

CREATE TABLE robot_user_sessions (
    session_key TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    role_name TEXT NOT NULL DEFAULT '默认',
    agent_mode TEXT NOT NULL DEFAULT 'eino_single',
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE skill_stats (
    skill_name TEXT PRIMARY KEY,
    total_calls INTEGER NOT NULL DEFAULT 0,
    success_calls INTEGER NOT NULL DEFAULT 0,
    failed_calls INTEGER NOT NULL DEFAULT 0,
    last_call_time DATETIME,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tool_executions (
    id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL,
    arguments TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    error TEXT,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    duration_ms INTEGER,
    partial_output TEXT,
    partial_output_bytes INTEGER NOT NULL DEFAULT 0,
    partial_output_truncated INTEGER NOT NULL DEFAULT 0,
    partial_output_updated_at DATETIME,
    owner_user_id TEXT,
    conversation_id TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE tool_stats (
    tool_name TEXT PRIMARY KEY,
    total_calls INTEGER NOT NULL DEFAULT 0,
    success_calls INTEGER NOT NULL DEFAULT 0,
    failed_calls INTEGER NOT NULL DEFAULT 0,
    last_call_time DATETIME,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vulnerabilities (
    id TEXT PRIMARY KEY,
    conversation_id TEXT,
    conversation_tag TEXT,
    task_tag TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    vulnerability_type TEXT,
    target TEXT,
    preconditions TEXT,
    reproduction_steps TEXT,
    evidence TEXT,
    impact TEXT,
    recommendation TEXT,
    retest_notes TEXT,
    retest_log TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    owner_user_id TEXT,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL
);

CREATE TABLE vulnerability_alert_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    external_user_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(vulnerability_id, platform, external_user_id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE
);

CREATE TABLE vulnerability_alert_subscriptions (
    user_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    min_severity TEXT NOT NULL DEFAULT 'high',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES rbac_users(id) ON DELETE CASCADE
);

CREATE TABLE vulnerability_retests (
    conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    source_conversation_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,
    pending_prompt TEXT NOT NULL DEFAULT ''
);

CREATE TABLE workflow_definitions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    graph_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE workflow_node_runs (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    status TEXT NOT NULL,
    input_json TEXT,
    output_json TEXT,
    error TEXT,
    started_at DATETIME NOT NULL,
    finished_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (run_id) REFERENCES workflow_runs(id) ON DELETE CASCADE
);

CREATE TABLE workflow_package_imports (
    id TEXT PRIMARY KEY,
    inspection_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('create','keep_existing','overwrite','rename')),
    source_workflow_id TEXT NOT NULL,
    target_workflow_id TEXT NOT NULL,
    resulting_workflow_id TEXT,
    result TEXT NOT NULL CHECK (result IN ('created','overwritten','renamed','kept_existing','skipped_identical','failed')),
    error_code TEXT,
    error_message TEXT,
    created_at DATETIME NOT NULL,
    applied_at DATETIME,
    FOREIGN KEY (inspection_id) REFERENCES workflow_package_inspections(id)
);

CREATE TABLE workflow_package_inspections (
    id TEXT PRIMARY KEY,
    package_hash TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    workflow_payload_json TEXT NOT NULL,
    inspection_json TEXT NOT NULL,
    source_workflow_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL,
    source_content_hash TEXT NOT NULL,
    source_graph_hash TEXT NOT NULL,
    local_conflict_state TEXT NOT NULL CHECK (local_conflict_state IN ('none','identical','id_conflict')),
    local_workflow_id TEXT,
    local_content_hash TEXT,
    local_graph_hash TEXT,
    created_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('ready','consumed','expired')),
    created_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME
);

CREATE TABLE workflow_runs (
    id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    workflow_version INTEGER NOT NULL DEFAULT 1,
    conversation_id TEXT,
    role_id TEXT,
    status TEXT NOT NULL,
    input_json TEXT,
    output_json TEXT,
    error TEXT,
    pending_hitl_node_id TEXT,
    pending_hitl_json TEXT,
    started_at DATETIME NOT NULL,
    finished_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL
);

CREATE INDEX idx_assets_domain ON assets(domain);

CREATE INDEX idx_assets_ip ON assets(ip);

CREATE INDEX idx_assets_last_scan ON assets(last_scan_at);

CREATE INDEX idx_assets_last_seen ON assets(last_seen_at);

CREATE INDEX idx_assets_owner ON assets(owner_user_id);

CREATE INDEX idx_assets_risk_level ON assets(risk_level);

CREATE INDEX idx_assets_risk_score ON assets(risk_score);

CREATE INDEX idx_assets_status ON assets(status);

CREATE INDEX idx_assets_vulnerability_count ON assets(vulnerability_count);

CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE INDEX idx_audit_logs_category ON audit_logs(category);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

CREATE INDEX idx_audit_logs_result ON audit_logs(result);

CREATE INDEX idx_batch_task_queues_created_at ON batch_task_queues(created_at);

CREATE INDEX idx_batch_task_queues_title ON batch_task_queues(title);

CREATE INDEX idx_batch_tasks_queue_id ON batch_tasks(queue_id);

CREATE INDEX idx_chat_upload_artifacts_conversation ON chat_upload_artifacts(conversation_id);

CREATE INDEX idx_chat_upload_artifacts_owner ON chat_upload_artifacts(owner_user_id);

CREATE INDEX idx_conversations_pinned ON conversations(pinned);

CREATE INDEX idx_conversations_host_id ON conversations(host_id);

CREATE INDEX idx_conversations_updated_at ON conversations(updated_at);

CREATE INDEX idx_knowledge_retrieval_logs_conversation ON knowledge_retrieval_logs(conversation_id);

CREATE INDEX idx_knowledge_retrieval_logs_created_at ON knowledge_retrieval_logs(created_at);

CREATE INDEX idx_knowledge_retrieval_logs_message ON knowledge_retrieval_logs(message_id);

CREATE INDEX idx_messages_conversation_id ON messages(conversation_id);

CREATE INDEX idx_model_token_usage_conversation ON model_token_usage(conversation_id);

CREATE INDEX idx_model_token_usage_created_at ON model_token_usage(created_at);

CREATE INDEX idx_model_token_usage_model ON model_token_usage(model);

CREATE INDEX idx_notification_reads_user_read_at ON notification_reads_by_user(user_id, read_at DESC);

CREATE INDEX idx_process_details_conversation_id ON process_details(conversation_id);

CREATE INDEX idx_process_details_message_id ON process_details(message_id);

CREATE INDEX idx_rbac_assignments_resource ON rbac_resource_assignments(resource_type, resource_id);

CREATE INDEX idx_rbac_assignments_user_resource ON rbac_resource_assignments(user_id, resource_type, resource_id);

CREATE INDEX idx_rbac_role_permissions_role ON rbac_role_permissions(role_id);

CREATE INDEX idx_rbac_user_roles_user ON rbac_user_roles(user_id);

CREATE INDEX idx_robot_binding_codes_expiry ON robot_binding_codes(expires_at);

CREATE INDEX idx_robot_user_bindings_user ON robot_user_bindings(rbac_user_id);

CREATE INDEX idx_robot_user_sessions_updated_at ON robot_user_sessions(updated_at);

CREATE INDEX idx_tool_executions_conversation ON tool_executions(conversation_id);

CREATE INDEX idx_tool_executions_owner ON tool_executions(owner_user_id);

CREATE INDEX idx_tool_executions_start_time ON tool_executions(start_time);

CREATE INDEX idx_tool_executions_status ON tool_executions(status);

CREATE INDEX idx_tool_executions_tool_name ON tool_executions(tool_name);

CREATE INDEX idx_vulnerabilities_conversation_id ON vulnerabilities(conversation_id);

CREATE INDEX idx_vulnerabilities_conversation_tag ON vulnerabilities(conversation_tag);

CREATE INDEX idx_vulnerabilities_created_at ON vulnerabilities(created_at);

CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);

CREATE INDEX idx_vulnerabilities_status ON vulnerabilities(status);

CREATE INDEX idx_vulnerabilities_task_tag ON vulnerabilities(task_tag);

CREATE INDEX idx_workflow_definitions_enabled ON workflow_definitions(enabled);

CREATE INDEX idx_workflow_definitions_updated_at ON workflow_definitions(updated_at);

CREATE INDEX idx_workflow_node_runs_run ON workflow_node_runs(run_id);

CREATE INDEX idx_workflow_package_inspections_creator_expiry ON workflow_package_inspections(created_by, expires_at);

CREATE INDEX idx_workflow_runs_conversation ON workflow_runs(conversation_id);

CREATE INDEX idx_workflow_runs_status ON workflow_runs(status);

CREATE INDEX idx_workflow_runs_workflow ON workflow_runs(workflow_id);

CREATE UNIQUE INDEX uq_workflow_package_imports_actor_key ON workflow_package_imports(actor_user_id, idempotency_key);

CREATE UNIQUE INDEX uq_workflow_package_imports_inspection_success ON workflow_package_imports(inspection_id) WHERE result IN ('created','overwritten','renamed','kept_existing','skipped_identical');

CREATE TABLE hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'ssh',
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT '',
    auth_type TEXT NOT NULL DEFAULT 'password',
    secret_cipher TEXT NOT NULL DEFAULT '',
    passphrase_cipher TEXT NOT NULL DEFAULT '',
    group_name TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'unknown',
    last_error TEXT NOT NULL DEFAULT '',
    last_check_at DATETIME,
    last_seen_at DATETIME,
    os_info TEXT NOT NULL DEFAULT '',
    host_key TEXT NOT NULL DEFAULT '',
    owner_user_id TEXT,
    remark TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX idx_hosts_address ON hosts(address);

CREATE INDEX idx_hosts_group ON hosts(group_name);

CREATE INDEX idx_hosts_owner ON hosts(owner_user_id);

CREATE INDEX idx_hosts_status ON hosts(status);

-- IOC 情报库：攻击者档案（IP / 域名 / URL / 文件哈希 / 邮箱 / 文件名）。
-- 状态机：observed（观察）→ confirmed（确认）→ blocked（已封禁）；误判走 false_positive。
-- 只有 confirmed 的条目才允许被检测引擎当匹配源、才允许下发封禁。
CREATE TABLE ioc (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL DEFAULT 'ip',
    value TEXT NOT NULL,
    normalized TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'observed',
    confidence INTEGER NOT NULL DEFAULT 50,
    severity TEXT NOT NULL DEFAULT 'medium',
    source TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    expires_at DATETIME,
    owner_user_id TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX idx_ioc_type_norm ON ioc(ioc_type, normalized);
CREATE INDEX idx_ioc_status ON ioc(status);
CREATE INDEX idx_ioc_last_seen ON ioc(last_seen);

-- 一个 IOC 命中过哪些主机（攻击者档案与主机的关联）。
CREATE TABLE ioc_host_hit (
    id TEXT PRIMARY KEY,
    ioc_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '',
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1,
    blocked_at DATETIME,
    block_command TEXT NOT NULL DEFAULT '',
    unblock_command TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX idx_ioc_host_uniq ON ioc_host_hit(ioc_id, host_id);
CREATE INDEX idx_ioc_host_host ON ioc_host_hit(host_id);

-- 检测发现：日志命中与基线不符合项的落库形态。
-- 一台主机 + 来源 + 规则 + 主体（如来源 IP）唯一，重复检测只累加次数与最近时间，
-- 这样"这周 vs 上周"的差分可以直接从 first_seen / last_seen / hit_count 算出来。
CREATE TABLE detect_findings (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',       -- log_scan | baseline_audit
    batch_task_id TEXT,                    -- 哪一轮巡检产出（可空）
    kind TEXT NOT NULL DEFAULT '',         -- log | baseline
    rule_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',   -- open | acked | resolved | false_positive
    subject TEXT NOT NULL DEFAULT '',      -- 去重主体：来源 IP / 检查对象
    evidence TEXT NOT NULL DEFAULT '',
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX idx_findings_uniq ON detect_findings(host_id, source, rule_id, subject);
CREATE INDEX idx_findings_host ON detect_findings(host_id);
CREATE INDEX idx_findings_severity ON detect_findings(severity);
CREATE INDEX idx_findings_last_seen ON detect_findings(last_seen);

-- Agent 记忆：关键 / 长期 / 短期三级。
--   critical   关键记忆：永不自动过期，只能显式删除（例如"生产库禁止重启"）
--   long_term  长期记忆：永久保存，但 Agent 判定过时后可改可删（例如网络分段、命名习惯）
--   short_term 短期记忆：默认 30 天过期，Agent 可续期（例如"本周在排查某告警"）
-- 作用域：global（跨主机通用）/ host（绑定某台主机）/ user（绑定某个平台用户）。
CREATE TABLE agent_memory (
    id TEXT PRIMARY KEY,
    tier TEXT NOT NULL DEFAULT 'long_term',
    scope TEXT NOT NULL DEFAULT 'global',
    host_id TEXT,
    owner_user_id TEXT,
    mem_key TEXT NOT NULL,
    content TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_used_at DATETIME,
    expires_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX idx_agent_memory_uniq ON agent_memory(tier, scope, mem_key, IFNULL(host_id, ''), IFNULL(owner_user_id, ''));
CREATE INDEX idx_agent_memory_tier ON agent_memory(tier);
CREATE INDEX idx_agent_memory_host ON agent_memory(host_id);
CREATE INDEX idx_agent_memory_updated ON agent_memory(updated_at);

-- 漏洞情报：外部公开漏洞知识库（NVD + CISA KEV + EPSS + GHSA）。
-- 与 vulnerabilities（自发现有）不同，这张表是"外界已知什么"；命中主机后才写成 detect_findings。
CREATE TABLE vuln_intel (
    cve_id TEXT PRIMARY KEY,
    title TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    cvss_score REAL,
    cvss_vector TEXT NOT NULL DEFAULT '',
    published_at DATETIME,
    modified_at DATETIME,
    kev INTEGER NOT NULL DEFAULT 0,
    kev_added_at DATETIME,
    epss REAL,
    epss_percentile REAL,
    epss_updated_at DATETIME,
    source TEXT NOT NULL DEFAULT '',
    refs TEXT NOT NULL DEFAULT '',
    cwes TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX idx_vuln_intel_severity ON vuln_intel(severity);
CREATE INDEX idx_vuln_intel_kev ON vuln_intel(kev);
CREATE INDEX idx_vuln_intel_epss ON vuln_intel(epss);
CREATE INDEX idx_vuln_intel_modified ON vuln_intel(modified_at);

-- 结构化版本区间：NVD 的 cpeMatch 与 GHSA 的 vulnerableVersionRange 都落到这里，
-- 供"版本是否受影响"做三态判定（true / false / 无法判断）。
CREATE TABLE vuln_intel_range (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    criteria TEXT NOT NULL DEFAULT '',
    start_incl TEXT NOT NULL DEFAULT '',
    start_excl TEXT NOT NULL DEFAULT '',
    end_incl TEXT NOT NULL DEFAULT '',
    end_excl TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    patched_version TEXT NOT NULL DEFAULT '',
    UNIQUE(cve_id, criteria, start_incl, start_excl, end_incl, end_excl)
);

CREATE INDEX idx_vuln_intel_range_product ON vuln_intel_range(product);
CREATE INDEX idx_vuln_intel_range_cve ON vuln_intel_range(cve_id);

-- 公开 PoC / 利用链接（来自 GitHub 搜索聚合），蓝队用它判断"是否已有现成利用"。
CREATE TABLE vuln_intel_poc (
    cve_id TEXT NOT NULL,
    url TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    stars INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME,
    UNIQUE(cve_id, url)
);

CREATE INDEX idx_vuln_intel_poc_cve ON vuln_intel_poc(cve_id);

-- 每源同步状态：游标、最近成功时间、累计条数、最后错误。
CREATE TABLE vuln_intel_sync (
    source TEXT PRIMARY KEY,
    cursor TEXT NOT NULL DEFAULT '',
    last_sync_at DATETIME,
    total_synced INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1
);

-- ============================================================================
-- 威胁情报（threat intel）
--
-- 与 IOC 的根本区别：IOC 是「我研判出的结论」，带状态机、可封禁；
-- 威胁情报是「外部源观测到的事实」，只读、只当证据，永不自动封禁。
-- 两者之间只留一个显式动作：采纳（把外部观测写成一条 observed IOC）。
-- ============================================================================

-- 源注册与健康度。mode 区分查询式（lookup）与订阅式（feed），两条链路
-- 的调度、配额、落地表都不同，不能混用一个 provider。
-- 密钥不落这张表，只记录 requires_key，实际 key 走配置/环境变量。
CREATE TABLE threat_intel_source (
    source TEXT PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'lookup',
    enabled INTEGER NOT NULL DEFAULT 1,
    requires_key INTEGER NOT NULL DEFAULT 0,
    endpoint TEXT NOT NULL DEFAULT '',
    ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    rate_limit_per_minute INTEGER NOT NULL DEFAULT 0,
    daily_quota INTEGER NOT NULL DEFAULT 0,
    quota_used INTEGER NOT NULL DEFAULT 0,
    quota_reset_at DATETIME,
    last_ok_at DATETIME,
    last_error TEXT NOT NULL DEFAULT '',
    updated_at DATETIME NOT NULL
);

-- 查询式结果缓存。negative cache 与正样本同表：查过但没情报也要落一行
-- （verdict=unknown），否则同一个指标会被反复打到源上，配额很快见底。
-- category 区分两类情报，别把「开了 80 端口」当成「这个 IP 恶意」：
--   reputation —— 信誉/恶意判定（GreyNoise / AbuseIPDB / VT / ThreatFox）
--   exposure   —— 暴露面观测（Shodan InternetDB：端口、CPE、已知漏洞、标签）
CREATE TABLE threat_intel_cache (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    normalized TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'reputation',
    verdict TEXT NOT NULL DEFAULT 'unknown',
    -- tags 存 JSON 数组：缓存命中时要从这里还原标签，否则第二次查询
    -- 会把 CPE / eol-product 这类标签整块丢掉。
    tags TEXT NOT NULL DEFAULT '[]',
    payload TEXT NOT NULL DEFAULT '',
    http_status INTEGER NOT NULL DEFAULT 0,
    fetched_at DATETIME NOT NULL,
    expires_at DATETIME
);
CREATE UNIQUE INDEX idx_threat_intel_cache_key ON threat_intel_cache(source, indicator_type, normalized);
CREATE INDEX idx_threat_intel_cache_indicator ON threat_intel_cache(indicator_type, normalized);
CREATE INDEX idx_threat_intel_cache_expires ON threat_intel_cache(expires_at);

-- 订阅式 feed 落地。与 cache 分开：feed 是按源定期覆盖的全量集合，
-- cache 是单次按需查询结果，混表会让"这条是不是我主动查的"变成猜谜。
CREATE TABLE threat_intel_feed (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    normalized TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    malware TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 50,
    first_seen DATETIME,
    last_seen DATETIME,
    tags TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL DEFAULT '',
    fetched_at DATETIME NOT NULL
);
CREATE UNIQUE INDEX idx_threat_intel_feed_unique ON threat_intel_feed(source, indicator_type, normalized);
CREATE INDEX idx_threat_intel_feed_type ON threat_intel_feed(indicator_type);
CREATE INDEX idx_threat_intel_feed_category ON threat_intel_feed(category);
CREATE INDEX idx_threat_intel_feed_source ON threat_intel_feed(source);
