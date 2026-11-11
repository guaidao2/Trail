---
name: host-inspection-playbook
description: 主机巡检 playbook：只读体检的检查顺序、判读要点与输出格式，配合 host_inspect/host_list 使用。
metadata:
  tags: [运维, 巡检, host, inspection]
---

## 主机巡检 playbook

### 顺序（先广后窄）

1. `host_list` 确认目标（ID、协议、登录用户、最近探测状态）。
2. `host_probe` 确认在线并取系统信息（同时会刷新主机状态）。
3. `host_inspect` 全量巡检（system/load/disk/users/ports/logins/cron/suid/last）。
4. 对异常项用 `host_download` 取具体文件，或用 `host_exec` 跑定向命令（示例见下）。

### 判读要点

| 检查项 | 异常信号 |
|---|---|
| system/load | 负载持续高于核数、运行时长与预期不符（可能刚重启过） |
| disk | 使用率 > 85%、inode 耗尽 |
| users | UID 0 的非 root 账户、可登录的服务账户、近期新增账户 |
| ports | 对外监听的高位端口、数据库/缓存端口绑 0.0.0.0 |
| logins | 失败登录集中在少数 IP、成功登录来自异常地域 |
| cron | /tmp 下的脚本、curl/wget 外联、随机命名 |
| suid | 非系统目录的 SUID、非常见工具带 SUID |

### 定向命令示例

```bash
# 谁在监听
ss -tulnp | head -40
# 最近 7 天被改过的 web 文件
find /var/www -type f -mtime -7 | head -30
# 某个进程的可执行文件与网络连接
ls -l /proc/<pid>/exe; ss -tunp | grep <pid>
```

### 输出格式

按检查项分组：`现象 → 证据（命令+输出片段）→ 影响判断 → 建议动作`；无异常项写"已检查，无异常"。
