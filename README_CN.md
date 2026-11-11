<div align="center">
  <img src="images/logo.svg" alt="溯痕 Trail Logo" width="200">
</div>

# 溯痕（CyberstrikeAI 蓝队版）

> 英文名 **Trail** · 仓库 `guaidao2/Trail` · 版本 **v1.0.0**

[中文](README_CN.md) | [English](README.md)

**溯痕是面向服务器运维与蓝队安全运营的 AI 执行中枢——日常运维意图转化为受治理的行动，每次巡检都留下可复核的证据。**

溯痕把规划、执行、人工监督、证据与复盘放在同一个可审计工作空间里：纳管主机后，Agent 通过 SSH/Telnet 远程完成日常体检、异常研判、取证与报告，无需在被管服务器上安装任何组件。项目基于 Go 构建，融合 Eino 智能体、MCP 原生工具、RAG 知识与可视化工作流。

**从这里开始：** [快速上手](#快速上手一条命令部署) · [中文文档](docs/zh-CN/README.md) · [安全加固](docs/zh-CN/security-hardening.md)

## 本版（v1.0.0）包含什么

这是从 [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) 分叉后重构的第一个正式版本，定位为**纯蓝队/运维构建**：

- **主机纳管**：以主机为唯一顶层对象；SSH（密码/私钥）与 Telnet 凭据使用 AES-256-GCM 加密入库，界面与接口只回显「已配置」，主机密钥采用 TOFU 首次信任并在后续连接强制校验。
- **远程运维**：命令执行、文件上传/下载（base64 管道，单次 8 MiB）、连通性探测与系统信息采集，全部经 `host:read` / `host:write` / `host:exec` 三级权限与审计。
- **定期巡检**：把主机巡检建成 cron 批量任务（复用批量任务调度器），每轮产出带证据的巡检报告；`host_inspect` 内置系统、负载、磁盘、登录、端口、SUID、定时任务等只读检查项。
- **蓝队脚本**：`tools/` 下提供基线核查、异常进程、SUID 审计、登录审计、WebShell 查杀、cron/服务审计、IOC 扫描、日志异常等巡检配方。
- **角色与技能**：11 个可编排子代理 + 12 个角色提示词（主机巡检、应急响应、日志分析、资产管理等），9 个 playbook 与 4 篇蓝队知识文档。
- **已移除红队面**：C2、WebShell 管理、项目/攻击链层与 42 个攻击性工具配方全部删除；RBAC 权限、i18n、文档、前端页面同步清理。
- **可运维性**：Web UI 端口可覆盖（`--port` / `CYBERSTRIKE_PORT`），单二进制部署，SQLite 自动建表与补列。

> [!IMPORTANT]
> 仅可对自有系统或已获得明确授权的目标使用溯痕。在共享或生产环境启用高风险命令执行能力前，请先阅读[安全模型](docs/zh-CN/security-model.md)和[安全加固指南](docs/zh-CN/security-hardening.md)。

## 特性速览

### 智能体与编排

- 🤖 **智能体执行层**：把「查一下这台机器」「按基线体检一遍」这类运维意图，转成受控、可审计的远程执行与取证。
- 🧩 **Eino 编排**：支持单智能体及 Deep、Plan-Execute、Supervisor 多智能体模式。
- 🔀 **工作流**：通过 Agent、工具、条件、审批和输出节点构建可复用流程。
- 🎭 **角色化值守**：主机巡检、应急响应、日志分析、资产管理、样本分析等角色各有聚焦的提示词与工具策略。

### 工具与知识扩展

- 🧰 **巡检工具**：内置 56 个运维/蓝队 YAML 配方（基线核查、异常进程、SUID、登录审计、WebShell 查杀、IOC、日志异常等），支持自定义扩展与按角色控制。
- 🔌 **MCP 集成**：支持 HTTP、stdio、SSE、外部 MCP 联邦和动态工具发现。
- ⏱️ **弹性工具执行**：阻塞型 MCP/工具调用交给 worker 执行，Agent 只有限等待；支持 `execution_id` 多轮等待、主动取消、单 server 熔断、并发限制和统一输出兜底。
- 🎯 **Agent Skills**：遵循标准 Skill 目录结构，支持渐进式按需加载。
- 📚 **知识库**：组合查询改写、向量检索、精排和结果后处理能力。
- 🖼️ **视觉分析**：使用独立视觉模型分析截图、验证码和 UI，对话中仅保留文字摘要。

### 安全治理与审计

- 🧑‍⚖️ **人机协同**：支持审批模式、工具白名单、审计 Agent 复核和决策追踪。
- 🛡️ **调用拦截**：「安全防护」下配置 MCP 执行前正则拦截、提醒模板和试匹配，默认启用政府域名保护。详见[调用拦截](docs/zh-CN/tool-call-guard.md)。
- 🔐 **平台 RBAC**：支持多用户、系统及自定义角色、权限 Scope、资源归属和显式授权。
- 🔒 **安全与审计**：提供登录保护、审计日志、SQLite 持久化和行动证据留存。
- 📄 **结果治理**：数据库保存与 Agent 实际看到的同一份兜底后工具结果，恢复路径会再次防御历史超大输出，前端详情也有展示保护。详见[工具执行治理](docs/zh-CN/tool-execution-governance.md)。

### 安全运营管理

- 🗂️ **主机与对话**：对话可绑定纳管主机，主机是唯一的顶层对象；历史会话支持分组、置顶与批量管理。
- 🗂️ **资产管理**：统一归档和去重域名、IP、端口与服务，支持 XLSX/CSV 导入导出、高级筛选与保存视图、责任和业务属性、跨页批量维护、重复资产合并，并跟踪扫描覆盖、关联漏洞和风险状态。详见[资产管理指南](docs/zh-CN/asset-management.md)。
- 🛡️ **风险与发现**：巡检/扫描产出的风险项支持分级、状态流转、过滤与统计看板，可导出 Markdown / Word。
- 📋 **批量任务**：支持任务队列、编辑、状态跟踪和结果留存。
- 📱 **机器人接入**：支持个人微信、企业微信、钉钉、飞书、Telegram、Slack、Discord 和 QQ。

### 运维与蓝队巡检

- 🖥️ **主机纳管**：纳管 SSH / Telnet 主机（密码或私钥），凭据 AES-256-GCM 加密存储、界面与 API 不回显；支持连通性探测、远程命令与文件传输。
- 🩺 **主机体检**：基线核查、异常进程与服务、SUID 与计划任务审计、登录与日志异常。
- 🔍 **事件研判**：把巡检与日志证据交给 Agent 逐条核验，产出可复核的结论而非猜测。
- 📊 **合规与漏洞面**：容器与云配置合规扫描、资产漏洞扫描、镜像与依赖风险。
- 🧾 **报告与留痕**：巡检结论落库，按项目归档，支持导出 Markdown / Word。

> 高风险命令执行仅在获得明确授权的范围内启用，所有执行都记录在审计日志中。使用前请阅读[安全模型](docs/zh-CN/security-model.md)和[安全加固指南](docs/zh-CN/security-hardening.md)。

## 工具概览

系统预置 56 个运维/蓝队工具配方，覆盖巡检、合规、取证与情报：

<details>
<summary><strong>查看完整工具分类</strong></summary>

- **网络与资产扫描**：nmap、masscan、rustscan、arp-scan、nbtscan
- **漏洞与暴露面**：nuclei、nikto、zap、wafw00f
- **容器与编排**：trivy、clair、kube-bench、kube-hunter、falco
- **云与配置合规**：prowler、scout-suite、cloudmapper、terrascan、checkov
- **取证与样本分析**：volatility3、foremost、exiftool、binwalk、strings、xxd、steghide、zsteg
- **二进制分析**：radare2、ghidra、objdump、checksec
- **域名与情报**：subfinder、amass、dnsenum、fierce、fofa、zoomeye、quake、shodan、virustotal
- **应用与 API 检查**：graphql-scanner、api-schema-analyzer、jwt-analyzer、http-framework-test
- **系统辅助**：exec、execute-python-script、install-python-package

</details>

工具定义、自定义方式与使用说明见 [tools/README.md](tools/README.md)。

## 基础使用

### 快速上手（一条命令部署）

**环境要求：**
- Go 1.25+（[下载安装](https://go.dev/dl/)，以 `go.mod` 为准）
- Python 3.10+ ([下载安装](https://www.python.org/downloads/))

**一条命令部署：**
```bash
git clone https://github.com/guaidao2/Trail.git
cd Trail
chmod +x run.sh && ./run.sh
```

`run.sh` 脚本会自动完成：
- ✅ 检查并验证 Go 和 Python 环境
- ✅ 创建 Python 虚拟环境
- ✅ 安装 Python 依赖包
- ✅ 下载 Go 依赖模块
- ✅ 编译构建项目
- ✅ 启动服务器

**验证是否启动成功：**

1. 确认终端显示 `● ONLINE`，并在其后给出实际 Web UI 地址。
2. 打开该地址；默认 HTTPS 使用本地自签证书，首次访问需接受一次浏览器证书提示。
3. 全新安装时，妥善保存 `ADMIN SETUP REQUIRED` 下仅展示一次的 `admin` 密码，登录后立即修改。

**网络默认：** `run.sh` 会以 **`--https`** 并传入项目根 **`config.yaml`** 启动（本机自签证书，多路流式场景更稳）。只要明文 HTTP 用 **`./run.sh --http`**。生产环境在 **`config.yaml`** 的 **`server.tls_cert_path` / `server.tls_key_path`** 配正式证书（见文件内注释）。手动启动可加 **`--https`** 或环境变量 **`CYBERSTRIKE_HTTPS=1`**；`-config` 写错时程序会在终端提示正确写法。

**首次配置：**
1. **配置 AI 通道**（首次使用前必填）
   - 启动后在浏览器打开 **`https://127.0.0.1:8080/`**（或 **`https://localhost:8080/`**；端口以 `config.yaml` 中 **`server.port`** 为准，默认 8080），并按提示信任自签证书。若使用 **`./run.sh --http`**，则改用 **`http://`** 访问。
   - 进入 `系统设置` → `基本设置` → `AI 通道配置`，新增或编辑通道，填写 API 提供商、Base URL、API Key、模型和 Token 上限，点击 **保存更改**。左侧通道列表支持设为默认、复制、删除和批量探活。
     ```yaml
     ai:
       default_channel: openai-main
       channels:
         openai-main:
           name: OpenAI Main
           provider: openai_compatible
           api_key: "${OPENAI_API_KEY}"
           base_url: "https://api.openai.com/v1"  # 或 https://api.deepseek.com/v1
           model: "gpt-4o"  # 或 deepseek-chat, qwen3-max 等
           max_total_tokens: 120000
           max_completion_tokens: 16384
     ```
   - 或启动前直接编辑 `config.yaml` 文件。`ai.default_channel` 会作为新对话和未显式选择通道任务的默认模型；对话页也可以在会话设置里选择某个已保存通道。
2. **登录系统** - 首次启动时控制台会显示自动生成的 `admin` 初始密码；也可在「平台权限 → 用户管理」中创建账号
3. **安装安全工具（可选）** - 按需安装 `tools/` 目录中的工具；未安装的工具在执行时会自动跳过或改用替代方案。常用示例：

   **macOS（Homebrew）：**
   ```bash
   brew install nmap masscan sqlmap nikto gobuster ffuf hydra hashcat nuclei subfinder
   ```

   **Linux（Kali / Debian / Ubuntu）：**
   ```bash
   sudo apt update
   sudo apt install -y nmap masscan sqlmap nikto gobuster hydra hashcat john binwalk
   # 部分发行版需自行安装：ffuf、nuclei、subfinder 等可用 go install 或见各工具官网
   ```

   完整工具列表见 `tools/` 目录；各工具安装方式以官方文档为准。

**其他启动方式：**
```bash
# 直接运行（需自行配环境）；与 run.sh 默认一致可加 --https
go run ./cmd/server --https

# 手动编译
go build -o trail ./cmd/server
./trail --https
```

若日志出现 `client sent an HTTP request to an HTTPS server`，说明仍有客户端用 **`http://`** 访问只提供 HTTPS 的端口，请改为 **`https://`**。

**说明：** Python 虚拟环境（`venv/`）由 `run.sh` 自动创建和管理。需要 Python 的工具（如 `api-fuzzer`、`http-framework-test` 等）会自动使用该环境。

### 版本升级与兼容性

**优先用平台自带的「一键更新」**（控制台「系统设置 → 一键更新」，或 `./trail -update` /
`-check-update` / `-update-rollback`）：它从**更新源仓库**（默认官方仓库，可一处配置改成自己的二开或镜像）
拉取默认分支的最新代码，快进后重编译并原子换二进制，你的 `roles/skills/tools/agents/data/config.yaml`
会被原样保留（结果里逐个点名保留了什么，只有 `config.yaml` 的 `version` 字段会随新代码同步，让页头版本号与代码对上），
本地源码有改动或本地历史与更新源分叉时它会拒绝而不是覆盖。
详见 [部署指南](docs/zh-CN/deployment.md)。

更新源是 `config.yaml` `update` 段里的一个仓库地址（`repo`），也可以在控制台「一键更新」页填写保存
（默认是溯痕自己的仓库；想跟随自己的二开或镜像也只需改这一处）。解压安装（目录里没有 git）也能在同一页
「预览并接入」后进入一键更新。

**没有独立的升级脚本**：上游的 `upgrade.sh` 会从红队仓库拉代码，在蓝队分支上等同于把代码换回红队版，已移除。
升级只走上面的「一键更新」。

如果升级失败：git 工作树里直接 `./trail -update-rollback`（回到那次更新前的提交与二进制）；
tarball 安装则从 `.update-backup/` 恢复，或手动拷回 `data/` 和 `config.yaml` 后再运行 `./run.sh`。

⚠️ **升级前必读：** 请查看目标版本的 Release Notes，确认配置、数据库和 API 是否变化。即使只是补丁版本也应先备份，不能仅凭版本号判断兼容性。


## 配置

请以 [`config.example.yaml`](config.example.yaml) 作为权威配置模板，只复制当前环境需要的配置。最少需要配置服务监听地址和一个 AI 通道：

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

`openai` 是兼容旧版本的运行时字段，新配置优先维护 `ai.channels`。不要提交真实凭证。将服务暴露到 localhost 之外前，请阅读[配置参考](docs/zh-CN/configuration.md)、[推荐配置画像](docs/zh-CN/configuration-profiles.md)和[安全加固指南](docs/zh-CN/security-hardening.md)。

## 相关文档

- **新用户：** [部署指南](docs/zh-CN/deployment.md) → [配置参考](docs/zh-CN/configuration.md) → [排错指南](docs/zh-CN/troubleshooting.md)
- **运维人员：** [配置画像](docs/zh-CN/configuration-profiles.md) → [安全加固](docs/zh-CN/security-hardening.md) → [运维 Runbooks](docs/zh-CN/runbooks.md)
- **集成开发：** [API 参考](docs/zh-CN/api-reference.md) → [API Recipes](docs/zh-CN/api-recipes.md) → [MCP 联邦](docs/zh-CN/mcp-federation.md)
- **项目贡献：** [开发者指南](docs/zh-CN/developer-guide.md) → [测试指南](docs/zh-CN/testing.md) → [贡献规范](docs/zh-CN/contributing-guide.md)
- **全部专题：** [中文文档](docs/zh-CN/README.md) · [双语文档索引](docs/README.md)

## 项目结构

```
Trail/
├── cmd/                 # Web 服务、MCP stdio 入口及辅助工具
├── internal/            # Agent、MCP 核心、路由与安全执行器
├── web/                 # 前端静态资源与模板
├── tools/               # YAML 工具目录（含 48 个示例）
├── roles/               # 角色配置文件目录（含 11 个预设角色）
├── skills/              # Agent Skills 目录（SKILL.md + 可选文件；示例 cyberstrike-eino-demo）
├── agents/              # 多代理 Markdown（orchestrator.md + 子代理 *.md）
├── docs/                # 专题文档（部署、配置、安全、API、知识库等）
├── images/              # 文档配图
├── config.yaml          # 运行配置
├── run.sh               # 启动脚本
└── README*.md
```

## 基础体验示例

```
扫描 192.168.1.1 的开放端口
对 192.168.1.1 做 80/443/22 重点扫描
检查 https://example.com/page?id=1 是否存在 SQL 注入
枚举 https://example.com 的隐藏目录与组件漏洞
获取 example.com 的子域并批量执行 nuclei
```

## 进阶剧本示例

```
加载侦察剧本：先 amass/subfinder，再对存活主机做服务识别与配置核查。
把巡检输出交给 Agent 逐条核验，产出可复核的结论与证据引用。
将 5MB nuclei 报告压缩并生成摘要，附加到对话记录。
构建最新一次巡检的事件时间线，只导出风险 >= 高的节点列表。
```

---

## 上游项目

溯痕是 [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) 的蓝队化分支。上游曾加入 [404 星链计划](https://github.com/knownsec/404StarLink) 等社区计划，相关荣誉与社群均属于上游项目；本分支沿用其 Apache-2.0 许可与工程基座，问题反馈与支持请以上游仓库为准。

## 许可证与署名

- **开源协议**：沿用上游的 **Apache License 2.0**，不做变更；完整条款见 [LICENSE](LICENSE)。
- **本项目**：溯痕（Trail）由 **guaidao2 & coolmoon** 维护。
- **上游与致谢**：溯痕基于 [CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI)（作者 **公明 / Ed1s0nZ**，镜像仓库 [AIPentest/CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI)）重构而来。
  感谢原作者搭建的 Eino 智能体、MCP 原生工具、工作流与前端工程基座——本次改造是在这套基座上裁掉红队面、补齐主机纳管与蓝队巡检能力，没有上游就没有溯痕。

依照 Apache-2.0 第 4 条，修改说明与归属声明见 [NOTICE](NOTICE)。

---

## ⚠️ 免责声明

**本工具仅供自有系统与已授权环境使用！**

溯痕面向服务器运维与蓝队安全运营，旨在帮助运维人员和蓝队分析人员在**获得明确授权**的范围内完成日常巡检、异常研判与应急响应。

**使用本工具即表示您同意：**
- 仅在您拥有明确书面授权的系统上使用此工具
- 遵守所有适用的法律法规和道德准则
- 对任何未经授权的使用或滥用行为承担全部责任
- 不会将本工具用于任何非法或恶意目的

**开发者不对任何滥用行为负责！** 请确保您的使用符合当地法律法规，并获得目标系统所有者的明确授权。

部署加固建议见 [安全加固指南](docs/zh-CN/security-hardening.md)。

---

欢迎提交 Issue/PR 贡献新的工具模版或优化建议！
