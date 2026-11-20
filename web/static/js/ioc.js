/*
 * IOC 情报库页面：列表 / 筛选 / 详情（命中主机）/ 新增更新 / 状态流转 / 删除。
 *
 * 封禁与解封不在这个页面做：它们要在目标主机上真的执行命令，
 * 由 Agent 调用 ioc_block / ioc_unblock（默认 dry_run），页面上只显示封禁留痕。
 */
(function () {
    let iocCache = [];

    function el(id) {
        return document.getElementById(id);
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // 全局只有 apiFetch（auth.js 提供，带鉴权头）；把"非 2xx 抛错 + 解析 JSON"封装在这里，
    // 避免每个调用点各写一遍，也避免误以为是全局函数（apiFetchJSON 在 hosts.js 里是私有的）。
    async function apiFetchJSON(url, options) {
        const res = await apiFetch(url, options);
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok) {
            throw new Error(data.error || ('请求失败 (' + res.status + ')'));
        }
        return data;
    }

    // 翻译取词：优先 i18n，缺键时回退到中文原文（不显示 key）。
    function tt(key, fallback) {
        try {
            if (typeof window.t === 'function') {
                const v = window.t(key);
                // 空字符串是合法译文（例如英文的 "共" 前缀就翻译成空串），
                // 只有"没拿到值"或"原样返回 key"才算缺键。
                if (typeof v === 'string' && v !== key) return v;
            }
        } catch (e) { /* ignore */ }
        return fallback;
    }

    // 时间统一走全局 formatTime（RFC3339 / SQLite 都能解析），避免表格里出现原始时间戳。
    function fmtTime(value) {
        if (!value) return '-';
        try {
            if (typeof window.formatTime === 'function') {
                const v = window.formatTime(value);
                if (v) return v;
            }
        } catch (e) { /* ignore */ }
        return String(value);
    }

    const STATUS_LABEL = {
        observed: 'ioc.statusObserved',
        confirmed: 'ioc.statusConfirmed',
        blocked: 'ioc.statusBlocked',
        false_positive: 'ioc.statusFalsePositive',
    };

    const STATUS_COLOR = {
        observed: '#64748b',
        confirmed: '#ca8a04',
        blocked: '#dc2626',
        false_positive: '#0891b2',
    };

    function statusLabel(s) {
        const key = STATUS_LABEL[String(s || 'observed')];
        return key ? tt(key, String(s || 'observed')) : String(s || 'observed');
    }

    function statusBadge(status) {
        const s = String(status || 'observed');
        const color = STATUS_COLOR[s] || '#64748b';
        return '<span style="display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;color:#fff;background:'
            + color + '">' + esc(statusLabel(s)) + '</span>';
    }

    function severityBadge(sev) {
        const s = String(sev || 'medium').toLowerCase();
        const color = s === 'critical' ? '#dc2626' : s === 'high' ? '#ea580c'
            : s === 'medium' ? '#ca8a04' : s === 'low' ? '#0891b2' : '#64748b';
        return '<span style="display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;color:#fff;background:'
            + color + '">' + esc(s) + '</span>';
    }

    function renderSummary(payload) {
        const box = el('ioc-status-summary');
        if (!box) return;
        const by = payload.by_status || {};
        const order = ['observed', 'confirmed', 'blocked', 'false_positive'];
        const parts = order
            .filter(function (k) { return by[k]; })
            .map(function (k) { return esc(statusLabel(k)) + ' <strong>' + esc(String(by[k])) + '</strong>'; });
        const prefix = tt('ioc.totalPrefix', '共');
        const suffix = tt('ioc.totalSuffix', '条');
        box.innerHTML = (prefix ? prefix + ' ' : '') + '<strong>' + esc(String(payload.total || 0)) + '</strong>'
            + (suffix ? ' ' + suffix : '')
            + (parts.length ? '　' + parts.join('　') : '');
    }

    let expandedIocId = '';
    const iocDetailCache = {};

    function renderDetailRow(id) {
        const detail = iocDetailCache[id];
        const rows = detail && detail.hosts && detail.hosts.length
            ? detail.hosts.map(function (h) {
                return '<tr><td>' + esc(h.host_id) + '</td>'
                    + '<td>' + esc(h.source || '-') + '</td>'
                    + '<td><code>' + esc(h.rule_id || '-') + '</code></td>'
                    + '<td>' + esc(String(h.hit_count)) + '</td>'
                    + '<td>' + esc(fmtTime(h.last_seen)) + '</td>'
                    + '<td>' + (h.blocked_at ? esc(tt('ioc.statusBlocked', '已封禁')) + ' ' + esc(fmtTime(h.blocked_at)) : '-') + '</td>'
                    + '<td><code>' + esc(h.unblock_command || '-') + '</code></td></tr>';
            }).join('')
            : '<tr><td colspan="7">' + esc(tt('ioc.detailNoHosts', '还没有命中记录')) + '</td></tr>';
        return '<tr class="ioc-detail-row"><td colspan="9">'
            + (detail ? '' : esc(tt('ioc.loading', '加载中…')))
            + (detail ? '<div class="table-container"><table class="data-table"><thead><tr>'
                + '<th>' + esc(tt('hosts.title', '主机')) + '</th>'
                + '<th>' + esc(tt('hosts.findingSource', '来源')) + '</th>'
                + '<th>' + esc(tt('hosts.findingRule', '规则')) + '</th>'
                + '<th>' + esc(tt('ioc.colHits', '命中次数')) + '</th>'
                + '<th>' + esc(tt('ioc.colLastSeen', '最近出现')) + '</th>'
                + '<th>' + esc(tt('ioc.colStatus', '状态')) + '</th>'
                + '<th>' + esc(tt('ioc.actionUndo', '撤销命令')) + '</th>'
                + '</tr></thead><tbody>' + rows + '</tbody></table></div>'
                + (detail.ioc && detail.ioc.note ? '<p class="page-hint">' + esc(detail.ioc.note) + '</p>' : '')
                : '')
            + '</td></tr>';
    }

    function renderList(items) {
        const tbody = el('ioc-body');
        if (!tbody) return;
        if (!items || !items.length) {
            tbody.innerHTML = '<tr><td colspan="9">' + esc(tt('ioc.empty', '暂无情报')) + '</td></tr>';
            return;
        }
        const rows = [];
        items.forEach(function (r) {
            const canMarkFalsePositive = r.status === 'observed' || r.status === 'confirmed';
            const expanded = expandedIocId === r.id;
            const actions = '<button class="btn-secondary btn-sm" data-require-permission="ioc:read" onclick="showIOCDetail(\'' + esc(r.id) + '\')">'
                + esc(expanded ? tt('ioc.actionCollapse', '收起') : tt('ioc.actionDetail', '详情')) + '</button> '
                + (r.status === 'observed'
                    ? '<button class="btn-secondary btn-sm" data-require-permission="ioc:write" onclick="setIOCStatus(\'' + esc(r.id) + '\',\'confirmed\')">' + esc(tt('ioc.actionConfirm', '确认')) + '</button> '
                    : '')
                + (canMarkFalsePositive
                    ? '<button class="btn-secondary btn-sm" data-require-permission="ioc:write" onclick="setIOCStatus(\'' + esc(r.id) + '\',\'false_positive\')">' + esc(tt('ioc.actionFalsePositive', '误报')) + '</button> '
                    : '')
                + '<button class="btn-danger btn-sm" data-require-permission="ioc:write" onclick="deleteIOC(\'' + esc(r.id) + '\')">' + esc(tt('ioc.actionDelete', '删除')) + '</button>';
            rows.push('<tr>'
                + '<td><code>' + esc(r.value) + '</code></td>'
                + '<td>' + esc(r.type) + '</td>'
                + '<td>' + statusBadge(r.status) + '</td>'
                + '<td>' + severityBadge(r.severity) + '</td>'
                + '<td>' + esc(String(r.confidence)) + '</td>'
                + '<td>' + esc(String(r.host_count || 0)) + '</td>'
                + '<td>' + esc(String(r.hit_count || 0)) + '</td>'
                + '<td>' + esc(fmtTime(r.last_seen)) + '</td>'
                + '<td>' + actions + '</td>'
                + '</tr>');
            if (expanded) rows.push(renderDetailRow(r.id));
        });
        tbody.innerHTML = rows.join('');
    }

    async function loadIOC() {
        const tbody = el('ioc-body');
        if (tbody) tbody.innerHTML = '<tr><td colspan="9">' + esc(tt('ioc.loading', '加载中…')) + '</td></tr>';
        try {
            const params = new URLSearchParams();
            const kw = el('ioc-search') ? el('ioc-search').value.trim() : '';
            if (kw) params.set('keyword', kw);
            const status = el('ioc-status-filter') ? el('ioc-status-filter').value : '';
            if (status) params.set('status', status);
            const type = el('ioc-type-filter') ? el('ioc-type-filter').value : '';
            if (type) params.set('type', type);
            params.set('page_size', '100');
            const payload = await apiFetchJSON('/api/ioc?' + params.toString());
            iocCache = payload.items || [];
            renderSummary(payload);
            renderList(iocCache);
        } catch (err) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="9">' + esc(err.message) + '</td></tr>';
        }
    }

    async function showIOCDetail(id) {
        // 行内展开：再点一次收起；详情按 id 缓存，避免重复请求。
        if (expandedIocId === id) {
            expandedIocId = '';
            renderList(iocCache);
            return;
        }
        expandedIocId = id;
        renderList(iocCache);
        if (iocDetailCache[id]) return;
        try {
            const payload = await apiFetchJSON('/api/ioc/' + encodeURIComponent(id));
            iocDetailCache[id] = { ioc: payload.ioc || {}, hosts: payload.hosts || [] };
        } catch (err) {
            delete iocDetailCache[id];
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        }
        renderList(iocCache);
    }

    async function saveIOC() {
        const value = el('ioc-form-value') ? el('ioc-form-value').value.trim() : '';
        if (!value) {
            if (typeof showNotification === 'function') showNotification(tt('ioc.fieldValue', '值') + ' ' + '∅', 'error');
            return;
        }
        try {
            await apiFetchJSON('/api/ioc', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    value: value,
                    type: el('ioc-form-type') ? el('ioc-form-type').value : 'ip',
                    status: el('ioc-form-status') ? el('ioc-form-status').value : 'observed',
                    severity: el('ioc-form-severity') ? el('ioc-form-severity').value : 'medium',
                    confidence: el('ioc-form-confidence') ? Number(el('ioc-form-confidence').value) : 50,
                    source: 'manual',
                    note: el('ioc-form-note') ? el('ioc-form-note').value : '',
                }),
            });
            if (el('ioc-form-value')) el('ioc-form-value').value = '';
            if (el('ioc-form-note')) el('ioc-form-note').value = '';
            closeIOCEditor();
            await loadIOC();
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        }
    }

    async function setIOCStatus(id, status) {
        try {
            delete iocDetailCache[id];
            if (expandedIocId === id) expandedIocId = '';
            await apiFetchJSON('/api/ioc/' + encodeURIComponent(id) + '/status', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: status }),
            });
            await loadIOC();
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        }
    }

    async function deleteIOC(id) {
        if (typeof window.confirm === 'function' && !window.confirm(tt('ioc.deleteConfirm', '删除这条情报及其命中记录？'))) {
            return;
        }
        try {
            await apiFetchJSON('/api/ioc/' + encodeURIComponent(id), { method: 'DELETE' });
            delete iocDetailCache[id];
            if (expandedIocId === id) expandedIocId = '';
            await loadIOC();
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        }
    }

    function openIOCEditor() {
        const modal = el('ioc-edit-modal');
        if (modal) modal.style.display = 'flex';
        const input = el('ioc-form-value');
        if (input && typeof input.focus === 'function') input.focus();
    }

    function closeIOCEditor() {
        const modal = el('ioc-edit-modal');
        if (modal) modal.style.display = 'none';
    }

    window.openIOCEditor = openIOCEditor;
    window.closeIOCEditor = closeIOCEditor;
    window.loadIOC = loadIOC;
    window.showIOCDetail = showIOCDetail;
    window.saveIOC = saveIOC;
    window.setIOCStatus = setIOCStatus;
    window.deleteIOC = deleteIOC;
    window.initIOCPage = function initIOCPage() {
        loadIOC();
    };
})();
