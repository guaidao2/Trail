---
name: baseline-hardening
description: 基线加固指南：SSH、账户、权限、日志、补丁与防火墙的最小加固集，配合基线核查脚本使用。
metadata:
  tags: [运维, 基线, hardening, compliance]
---

## 基线加固最小集

### SSH

- `PermitRootLogin no`（或 `prohibit-password`），`PasswordAuthentication no`（改密钥）
- 限制 `AllowUsers`/`AllowGroups`，改默认端口不是安全措施但能减少噪音
- 变更前确认有可用的密钥登录通道，避免自锁

### 账户

- UID 0 只保留 root；删除或锁定无用账户
- 服务账户 shell 设为 `/usr/sbin/nologin`
- 定期核对 `sudoers` 与 sudo 组成员

### 权限与持久化

- 清理非系统目录的 SUID/SGID
- 计划任务与服务单元纳入变更管理，禁止匿名写入
- `/etc/cron.*`、`/etc/systemd/system` 目录权限收紧

### 补丁与日志

- 安全更新定期执行（先测试再上生产）
- 认证日志与 Web 日志保留 ≥ 90 天，集中收集
- 关键文件完整性监控（`/etc/passwd`、`sshd_config`、站点目录）

### 验证

改完用 `baseline_check` + `login_audit` 复核，并把结论写进巡检报告。
