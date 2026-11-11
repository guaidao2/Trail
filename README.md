<div align="center">
  <img src="images/logo.svg" alt="Trail Logo" width="200" >
</div>

# Trail (CyberstrikeAI Blue)

> Chinese name **溯痕** · repository `guaidao2/Trail` · version **v1.0.0**

[中文](README_CN.md) | [English](README.md)

**Trail is the AI execution hub for server operations and blue-team security—where routine ops intent becomes governed execution and every inspection leaves reviewable evidence.**

Trail puts planning, execution, human oversight, evidence, and replay in one auditable workspace: onboard a host and the agent works on it over SSH/Telnet for health checks, triage, forensics, and reporting—no agent installed on the managed server. Built in Go, it combines Eino-powered agents, MCP-native tools, RAG knowledge, and visual workflows.

**Start here:** [Quick start](#quick-start-one-command-deployment) · [Documentation](docs/en-US/README.md) · [Security hardening](docs/en-US/security-hardening.md)

## What's in v1.0.0

This is the first release after forking [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) and refocusing it as a **blue-team / operations-only build**:

- **Host onboarding** — hosts are the only top-level object; SSH (password/key) and Telnet credentials are stored with AES-256-GCM, never echoed back, and host keys use TOFU trust with enforced verification afterwards.
- **Remote operations** — command execution, file upload/download (base64 pipeline, 8 MiB cap), connectivity probe and system facts, all gated by `host:read` / `host:write` / `host:exec` and fully audited.
- **Scheduled inspection** — host inspections are created as cron batch queues, each run producing an evidence-backed report; `host_inspect` covers system, load, disk, logins, ports, SUID, cron entries and more.
- **Blue-team recipes** — `tools/` ships baseline check, suspicious process, SUID audit, login audit, webshell hunt, cron/service audit, IOC scan and log anomaly recipes.
- **Roles and skills** — 11 orchestrated sub-agents and 12 role prompts (host inspection, incident response, log analysis, asset inventory, …), 9 playbooks and 4 blue-team knowledge documents.
- **Red-team surface removed** — C2, WebShell management, the project/attack-chain layers and 42 offensive tool recipes are gone, along with their RBAC permissions, i18n keys, docs and UI.
- **Operability** — Web UI port override (`--port` / `CYBERSTRIKE_PORT`), single binary, automatic SQLite schema creation and column reconciliation.

> [!IMPORTANT]
> Use Trail only on systems you own or are explicitly authorized to operate. For shared or production environments, review the [security model](docs/en-US/security-model.md) and [hardening guide](docs/en-US/security-hardening.md) before enabling high-risk command execution.

## Highlights

### Agents and orchestration

- 🤖 **Agentic execution** translates natural-language intent into governed, auditable security actions.
- 🧩 **Eino orchestration** supports single-agent execution plus Deep, Plan-Execute, and Supervisor multi-agent modes.
- 🔀 **Graph workflows** combine Agents, tools, conditions, approvals, and outputs into reusable flows.
- 🎭 **Role-based testing** provides focused prompts and tool policies for common security scenarios.

### Tools and knowledge

- 🧰 **Security tools** include 100+ curated YAML recipes with custom extensions and role-scoped access.
- 🔌 **MCP integration** supports HTTP, stdio, SSE, external federation, and dynamic tool discovery.
- ⏱️ **Resilient tool execution** runs blocking MCP/tool calls in workers with bounded agent waits, resumable `execution_id` polling, cancellation, per-server circuit breakers, concurrency limits, and unified output caps.
- 🎯 **Agent Skills** follow the standard Skill layout and support progressive, on-demand loading.
- 📚 **Knowledge base** combines query rewriting, vector retrieval, reranking, and result post-processing.
- 🖼️ **Vision analysis** uses a separate vision model for screenshots, captchas, and UI while retaining text summaries only.

### Governance and audit

- 🧑‍⚖️ **Human in the loop** provides approval modes, tool allowlists, audit-agent review, and traceable decisions.
- 🛡️ **Call blocking** under Security adds configurable regex checks before MCP execution, reminder templates, and dry runs, with government-domain protection enabled by default. See [Tool call blocking](docs/en-US/tool-call-guard.md).
- 🔐 **Platform RBAC** supports multiple users, system and custom roles, scoped permissions, ownership, and explicit assignments.
- 🔒 **Security and audit** provide authenticated access, audit logs, SQLite persistence, and operational evidence retention.
- 📄 **Result governance** stores the same capped tool result seen by the agent, protects resume paths from oversized historical output, and adds UI safeguards for large detail views. See [Tool Execution Governance](docs/en-US/tool-execution-governance.md).

### Security operations

- 📁 **Conversation management** provides pinning, renaming, and batch organization.
- 📂 **Projects and event timelines** connect cross-session facts, risk scoring, graph views, and step-by-step replay.
- 🗂️ **Asset management** normalizes and deduplicates domains, IP addresses, ports, and services; supports XLSX/CSV import and export, advanced filters and saved views, ownership and business metadata, cross-page bulk maintenance, and duplicate merging; and tracks scan coverage, linked vulnerabilities, and risk state. See the [Asset Management guide](docs/en-US/asset-management.md).
- 🛡️ **Vulnerability management** provides severity classification, lifecycle tracking, filtering, and statistics.
- 📋 **Batch tasks** provide queued execution, editing, status tracking, and retained results.
- 📱 **Chatbots** connect Personal WeChat, WeCom, DingTalk, Lark, Telegram, Slack, Discord, and QQ Bot.

### Operations and blue-team inspection

- 🖥️ **Host onboarding** covers SSH / Telnet hosts with password or key auth; credentials are stored with AES-256-GCM and never returned by the UI or API, and hosts support probing, remote commands, and file transfer.
- 🩺 **Host health checks** cover baselines, suspicious processes and services, SUID and cron audits, and login/log anomalies.
- 🔍 **Triage** hands inspection and log evidence to the agent, which produces reviewable conclusions instead of guesses.
- 📊 **Compliance and exposure** cover container/cloud config scanning, asset vulnerability scanning, and image/dependency risk.
- 🧾 **Reporting** stores conclusions per project and exports Markdown or Word.

> High-risk command execution is limited to explicitly authorized scope and every execution is written to the audit log. See the [security model](docs/en-US/security-model.md) and [hardening guide](docs/en-US/security-hardening.md).

## Tool Overview

Trail ships with 56 operation and blue-team tool recipes covering inspection, compliance, forensics, and intelligence:

<details>
<summary><strong>View the complete tool categories</strong></summary>

- **Network & Asset Scanning** – nmap, masscan, rustscan, arp-scan, nbtscan
- **Vulnerability & Exposure** – nuclei, nikto, zap, wafw00f
- **Containers & Orchestration** – trivy, clair, kube-bench, kube-hunter, falco
- **Cloud & Config Compliance** – prowler, scout-suite, cloudmapper, terrascan, checkov
- **Forensics & Sample Analysis** – volatility3, foremost, exiftool, binwalk, strings, xxd, steghide, zsteg
- **Binary Analysis** – radare2, ghidra, objdump, checksec
- **DNS & Intelligence** – subfinder, amass, dnsenum, fierce, fofa, zoomeye, quake, shodan, virustotal
- **App & API Checks** – graphql-scanner, api-schema-analyzer, jwt-analyzer, http-framework-test
- **System Helpers** – exec, execute-python-script, install-python-package

</details>

See [tools/README_EN.md](tools/README_EN.md) for tool definitions, customization, and usage notes.

## Basic Usage

### Quick Start (One-Command Deployment)

**Prerequisites:**
- Go 1.25+ ([Install](https://go.dev/dl/); required by `go.mod`)
- Python 3.10+ ([Install](https://www.python.org/downloads/))

**One-Command Deployment:**
```bash
git clone https://github.com/guaidao2/Trail.git
cd Trail
chmod +x run.sh && ./run.sh
```

The `run.sh` script will automatically:
- ✅ Check and validate Go & Python environments
- ✅ Create Python virtual environment
- ✅ Install Python dependencies
- ✅ Download Go dependencies
- ✅ Build the project
- ✅ Start the server

**Verify the startup:**

1. Confirm the terminal displays `● ONLINE` followed by the actual Web UI URL.
2. Open that URL; the default HTTPS mode uses a local self-signed certificate, so accept the browser warning once.
3. On a new installation, store the one-time `admin` password shown under `ADMIN SETUP REQUIRED`, sign in, and change it immediately.

**Networking defaults:** `run.sh` starts the server with **`--https`** and the repo **`config.yaml`** (local self-signed TLS; better for many concurrent streams). Use **`./run.sh --http`** for plain HTTP. In production, set **`server.tls_cert_path`** / **`server.tls_key_path`** in **`config.yaml`** (see comments there). For manual runs, add **`--https`** or **`CYBERSTRIKE_HTTPS=1`**; if **`-config`** is wrong, the binary prints a short usage hint on stderr.

**First-Time Configuration:**
1. **Configure AI channels** (required before first use)
   - After launch, open **`https://127.0.0.1:8080/`** (or **`https://localhost:8080/`**; replace **8080** with `server.port` in `config.yaml`) and accept the self-signed certificate warning once. If you used `./run.sh --http`, use **`http://`** instead.
   - Go to `System Settings` → `Basic Settings` → `AI Channel Configuration`, add or edit a channel, then fill in provider, Base URL, API key, model, and token limits. Click **Save changes**. The left channel list supports setting a default, copy, delete, and bulk probe.
     ```yaml
     ai:
       default_channel: openai-main
       channels:
         openai-main:
           name: OpenAI Main
           provider: openai_compatible
           api_key: "${OPENAI_API_KEY}"
           base_url: "https://api.openai.com/v1"  # or https://api.deepseek.com/v1
           model: "gpt-4o"  # or deepseek-chat, qwen3-max, etc.
           max_total_tokens: 120000
           max_completion_tokens: 16384
     ```
   - Or edit `config.yaml` directly before launching. `ai.default_channel` is used for new conversations and tasks that do not explicitly select a channel; the chat page can also select any saved channel per session.
2. **Login** - On first startup the console prints an auto-generated initial `admin` password; create accounts from **Platform permissions → User management**
3. **Install security tools (optional)** - Install tools from `tools/` as needed; missing tools are skipped or substituted at runtime. Common examples:

   **macOS (Homebrew):**
   ```bash
   brew install nmap masscan sqlmap nikto gobuster ffuf hydra hashcat nuclei subfinder
   ```

   **Linux (Kali / Debian / Ubuntu):**
   ```bash
   sudo apt update
   sudo apt install -y nmap masscan sqlmap nikto gobuster hydra hashcat john binwalk
   # On some distros, install ffuf/nuclei/subfinder via go install or upstream docs
   ```

   See the `tools/` directory for the full list; refer to each tool's official docs for install details.

**Alternative Launch Methods:**
```bash
# Direct Go run (set up env yourself); add --https to match run.sh defaults
go run ./cmd/server --https

# Manual build
go build -o trail ./cmd/server
./trail --https
```

If server logs show `client sent an HTTP request to an HTTPS server`, a client is still using **`http://`** on a TLS-only port—switch the URL to **`https://`**.

**Note:** The Python virtual environment (`venv/`) is automatically created and managed by `run.sh`. Tools that require Python (like `api-fuzzer`, `http-framework-test`, etc.) will automatically use this environment.

### Upgrade and Compatibility

**Prefer the platform's own one-click update** (console System settings -> One-click update, or
`./trail -update` / `-check-update` / `-update-rollback`): it pulls the newest commit of the
**update source repository**'s default branch (the official repository by default; one setting points
it at your own fork or a mirror), fast-forwards, rebuilds and swaps the binary atomically, keeps your
`roles/skills/tools/agents/data/config.yaml` untouched (the result names every file it kept; only
`config.yaml`'s `version` field is synced to the new code, so the header badge matches it), and
refuses - rather than overwrites - when source is modified locally or the local history has diverged.
See the [deployment guide](docs/en-US/deployment.md).

The update source is the `repo` entry under `update` in `config.yaml`, and it can also be set on the
console's "One-click update" page (it defaults to Trail's own repository; point it at your own fork or
mirror by changing this one value). Tarball installations can "preview and adopt" on the same page.

**There is no standalone upgrade script**: upstream's `upgrade.sh` pulls code from the red-team
repository, which on this blue-team fork would swap the codebase back to the red-team build. It has been
removed; upgrades go through "One-click update" only.

If an upgrade fails: in a git work tree run `./trail -update-rollback` (restores the pre-update commit and
binary); a tarball install restores from `.update-backup/`, or you copy `data/` and `config.yaml` back and
re-run `./run.sh`.

⚠️ **Before upgrading:** review the target release notes for configuration, database, and API changes. Backups are required even for patch upgrades; a version number alone is not a compatibility guarantee.


## Configuration

Use [`config.example.yaml`](config.example.yaml) as the authoritative configuration template and copy only the values required for your environment. At minimum, configure the server and one AI channel:

```yaml
server:
  host: "127.0.0.1"
  port: 8080
ai:
  default_channel: openai-main
  channels:
    openai-main:
      provider: openai_compatible
      api_key: "${OPENAI_API_KEY}"
      base_url: "https://api.openai.com/v1"
      model: "your-model"
```

`openai` is a backward-compatible runtime field; maintain new model settings in `ai.channels`. Do not commit real credentials. Review the [configuration reference](docs/en-US/configuration.md), [recommended profiles](docs/en-US/configuration-profiles.md), and [security hardening guide](docs/en-US/security-hardening.md) before exposing the service beyond localhost.

## Related documentation

- **New users:** [Deployment](docs/en-US/deployment.md) → [Configuration](docs/en-US/configuration.md) → [Troubleshooting](docs/en-US/troubleshooting.md)
- **Operators:** [Configuration profiles](docs/en-US/configuration-profiles.md) → [Security hardening](docs/en-US/security-hardening.md) → [Runbooks](docs/en-US/runbooks.md)
- **Integrators:** [API reference](docs/en-US/api-reference.md) → [API recipes](docs/en-US/api-recipes.md) → [MCP federation](docs/en-US/mcp-federation.md)
- **Contributors:** [Developer guide](docs/en-US/developer-guide.md) → [Testing](docs/en-US/testing.md) → [Contributing](docs/en-US/contributing-guide.md)
- **All topics:** [English documentation](docs/en-US/README.md) · [Bilingual documentation index](docs/README.md)

## Project Layout

```
Trail/
├── cmd/                 # Server, MCP stdio entrypoints, tooling
├── internal/            # Agent, MCP core, handlers, security executor
├── web/                 # Static SPA + templates
├── tools/               # YAML tool recipes (100+ examples provided)
├── roles/               # Role configurations (12+ predefined security testing roles)
├── skills/              # Agent Skills dirs (SKILL.md + optional files; demo: cyberstrike-eino-demo)
├── agents/              # Multi-agent Markdown (orchestrator.md + sub-agent *.md)
├── docs/                # Topic docs (deployment, config, security, API, knowledge base, etc.)
├── images/              # Docs screenshots & diagrams
├── config.yaml          # Runtime configuration
├── run.sh               # Convenience launcher
└── README*.md
```

## Basic Usage Examples

```
Scan open ports on 192.168.1.1
Perform a comprehensive port scan on 192.168.1.1 focusing on 80,443,22
Check if https://example.com/page?id=1 is vulnerable to SQL injection
Scan https://example.com for hidden directories and outdated software
Enumerate subdomains for example.com, then run nuclei against the results
```

## Advanced Playbooks

```
Load the recon-engagement template, run amass/subfinder, then fingerprint services and audit configuration on every live host.
Hand the inspection output to the agent and require reviewable conclusions with evidence.
Compress the 5 MB nuclei report, summarize critical CVEs, and attach the artifact to the conversation.
Build an event timeline for the latest engagement and export the node list with severity >= high.
```

---

## Upstream project

Trail is a blue-team fork of [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI). Community programs such as [404Starlink](https://github.com/knownsec/404StarLink) belong to the upstream project; this fork reuses its Apache-2.0 license and engineering foundation only. Please direct upstream-specific questions and community requests to the original repository.

## License & attribution

- **License**: unchanged from upstream — **Apache License 2.0** (see [LICENSE](LICENSE)).
- **This project**: Trail (溯痕) is maintained by **guaidao2 & coolmoon**.
- **Upstream & thanks**: Trail is a refactor of [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) by **公明 / Ed1s0nZ** (mirror: [AIPentest/CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI)).
  Thanks to the original author for the Eino agent runtime, MCP-native tooling, workflow engine and frontend foundation — this fork strips the red-team surface and adds host management plus blue-team inspection on top of that base. Without upstream there would be no Trail.

Modification notices and attribution per Apache-2.0 §4 are recorded in [NOTICE](NOTICE).

---

## ⚠️ Disclaimer

**This tool is for authorized operations and blue-team use only!**

Trail targets server operations and blue-team security: it helps operators and analysts run routine inspection, triage and incident response **within explicitly authorized scope**.

**By using this tool, you agree to:**
- Use this tool only on systems where you have clear written authorization
- Comply with all applicable laws, regulations, and ethical standards
- Take full responsibility for any unauthorized use or misuse
- Not use this tool for any illegal or malicious purposes

**The developers are not responsible for any misuse!** Please ensure your usage complies with local laws and regulations, and that you have obtained explicit authorization from the target system owner.

Deployment hardening guidance lives in [docs/en-US/security-hardening.md](docs/en-US/security-hardening.md).

---

Need help or want to contribute? Open an issue or PR—community tooling additions are welcome!
