# Configuration Profiles

[中文](../zh-CN/configuration-profiles.md)

These profiles are not full `config.yaml` files. They show the key sections that most affect safety and operability.

## Local Development

Goal: easy debugging with local capabilities.

Common startup:

```bash
chmod +x run.sh && ./run.sh
```

```yaml
server:
  host: 127.0.0.1
  port: 8080
  tls_enabled: true
  tls_auto_self_sign: true
auth:
  session_duration_hours: 12
audit:
  enabled: true
  retention_days: 7
multi_agent:
  enabled: true
  eino_skills:
    filesystem_tools: true
```

Not for shared or public use.

## Internal Team

Goal: shasecurity operations instance with audit and limited high-risk surface.

```yaml
server:
  host: 127.0.0.1
  port: 8080
  tls_enabled: false
auth:
  session_duration_hours: 12
audit:
  enabled: true
  retention_days: 30
monitor:
  retention_days: 90
mcp:
  enabled: false
hitl:
  default_reviewer: human
  tool_whitelist: [read_file, glob, grep, tool_search]
```

Pair with reverse-proxy HTTPS, IP allowlist, and backups.

## Knowledge-Only Assistant

Goal: use Trail as a knowledge-augmented assistant with minimal attack surface.

```yaml
mcp:
  enabled: false
knowledge:
  enabled: true
  base_path: knowledge_base
  retrieval:
    top_k: 5
    similarity_threshold: 0.4
multi_agent:
  eino_skills:
    filesystem_tools: false
```

Use read-only roles and avoid storing sensitive customer data.

## High-Audit Production

Goal: long-running production security-operations or security platform.

```yaml
auth:
  session_duration_hours: 8
audit:
  enabled: true
  retention_days: 90
monitor:
  retention_days: 180
hitl:
  default_reviewer: human
  retention_days: 180
  tool_whitelist: [read_file, glob, grep, tool_search]
multi_agent:
  eino_callbacks:
    enabled: true
    mode: log_only
    sse_trace_to_client: false
```

Pair with proxy auth, dedicated OS user, log collection, encrypted backups, and host group closeout cleanup.

## remote sessions Exercise Window

Goal: temporarily enable remote sessions only during authorized exercise.

```yaml
hitl:
  default_reviewer: human
  tool_whitelist: [read_file, glob, grep, tool_search]
audit:
  enabled: true
monitor:
  retention_days: 180
```

Requirements:

- confirm scope before exercise;
- separate listener ports from admin UI;
- run remote sessions cleanup afterward;

## External MCP Automation

Goal: connect trusted internal tool services.

```yaml
external_mcp:
  servers: {}
multi_agent:
  eino_middleware:
    tool_search_enable: true
    tool_search_min_tools: 20
hitl:
  default_reviewer: audit_agent
  tool_whitelist: [read_file, glob, grep, tool_search]
```

Guidance:

- every MCP tool needs clear schema;
- high-risk MCP tools stay out of allowlist;
- stdio MCP gets its own working directory;
- HTTP MCP must authenticate.
