# Configuration Reference

[中文](../zh-CN/configuration.md)

The main configuration file is `config.yaml`. Many fields are editable through the Web settings page, but not every field has the same hot-apply behavior.

## Remote hosts

```yaml
hosts:
  # Host credentials are encrypted with AES-256-GCM; the key comes from
  # CYBERSTRIKE_HOST_KEY or host_secret.key next to the database (0600).
```

- Managed host addresses, ports, users, and credentials live in SQLite; there is no separate master switch.
- Inspection recipes live in `tools/` (baseline_check, webshell_hunt, ...) and can be run by the agent or a schedule.

## Diagnostic logs

Alongside `log.output` (controlled by `log.level`), warnings and errors are saved as JSON Lines in `log/diagnostic-YYYY-MM-DD.log`, using the server’s local date. This independent warn-and-above output preserves existing context, caller information, and error stack traces; ordinary info/debug records are excluded and no extra request bodies or tool output are collected.

Configure `log.diagnostic_dir` (default `log`, relative to the working directory), `log.diagnostic_retention_days` (default 14, including today; nonpositive values use the default), or `log.diagnostic_disabled: true` to disable it. Restart after changing these settings. Files are created only when a diagnostic record is written; the first write each day removes expired files matching `diagnostic-YYYY-MM-DD.log`. Cleanup does not run while no diagnostic records are written. Write failures are reported to stderr without interrupting the primary log output.
