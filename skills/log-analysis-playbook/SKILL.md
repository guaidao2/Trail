---
name: log-analysis-playbook
description: 日志分析 playbook：认证/Web/系统日志的定位方法、聚合技巧与时间线还原。
metadata:
  tags: [运维, 蓝队, log, 日志分析]
---

## 日志分析 playbook

### 定位

| 目标 | 位置 |
|---|---|
| 认证 | `/var/log/auth.log`（Debian 系）、`/var/log/secure`（RHEL 系）、`last`/`lastb` |
| Web | nginx/apache access/error |
| 系统 | `journalctl -u <svc>`、`dmesg`、`syslog` |
| 应用 | 服务自身日志目录，优先看 error/timeout |

### 聚合技巧

```bash
# 失败登录来源 Top10
grep -hi "failed password" /var/log/auth.log | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head
# 404 密集来源
awk '$9==404 {print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head
# 扫描特征
grep -hE "(\.env|/admin|wp-login|\.git)" /var/log/nginx/access.log | tail -20
```

### 时间线还原

1. 选定可疑对象（IP / 账号 / URL / 进程）。
2. 按分钟聚合，找爆发点与持续时间。
3. 抽取原始日志行作为证据（含时间戳与文件路径）。
4. 判断是否成功（状态码、会话建立、后续动作）。

### 注意

- 日志轮转会让窗口变短；需要更长窗口用 `journalctl --since`。
- 单条可疑日志不足以定性；标注置信度与后续验证方法。
