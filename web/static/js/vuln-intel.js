/*
 * 漏洞情报页面：外部公开漏洞知识库（NVD + CISA KEV + EPSS + GHSA + PoC）。
 *
 * 与「漏洞管理」的区别：这里展示的是"外界已知什么"，属于知识；
 * 只有和主机软件清单匹配后才写成该主机的检测发现。
 */
(function () {
    let intelCache = [];
    let expandedCve = '';
    const detailCache = {};

    function el(id) { return document.getElementById(id); }

    // CVE 编号只允许字母数字与连字符，避免外部数据拼进 inline onclick。
    function safeCveId(v) {
        return String(v || '').replace(/[^A-Za-z0-9-]/g, '');
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function tt(key, fallback) {
        try {
            if (typeof window.t === 'function') {
                const v = window.t(key);
                if (typeof v === 'string' && v !== key) return v;
            }
        } catch (e) { /* ignore */ }
        return fallback;
    }

    async function apiFetchJSON(url, options) {
        const res = await apiFetch(url, options);
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok) throw new Error(data.error || ('请求失败 (' + res.status + ')'));
        return data;
    }

    function fmtTime(v) {
        if (!v) return '-';
        try {
            if (typeof window.formatTime === 'function') {
                const out = window.formatTime(v);
                if (out) return out;
            }
        } catch (e) { /* ignore */ }
        return String(v);
    }

    const SEVERITY_COLOR = {
        CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#0891b2', NONE: '#64748b',
    };

    function severityBadge(sev) {
        const s = String(sev || '').toUpperCase();
        if (!s) return '-';
        return '<span style="display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;color:#fff;background:'
            + (SEVERITY_COLOR[s] || '#64748b') + '">' + esc(s) + '</span>';
    }

    function kevBadge(kev) {
        return kev
            ? '<span style="display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;color:#fff;background:#b91c1c">KEV</span>'
            : '<span style="color:var(--text-secondary)">-</span>';
    }

    function renderSummary(payload) {
        const box = el('vuln-intel-summary');
        if (!box) return;
        const parts = [];
        parts.push(esc(tt('vulnIntel.totalPrefix', '共')) + ' <strong>' + esc(String(payload.count || 0)) + '</strong> ' + esc(tt('vulnIntel.totalSuffix', '条')));
        parts.push('KEV <strong>' + esc(String(payload.kev || 0)) + '</strong>');
        parts.push(esc(tt('vulnIntel.ranges', '版本区间')) + ' <strong>' + esc(String(payload.ranges || 0)) + '</strong>');
        const sync = (payload.sync || []).filter(function (s) { return s.last_sync_at; });
        if (sync.length) {
            parts.push(sync.map(function (s) {
                return esc(s.source) + ' ' + esc(fmtTime(s.last_sync_at));
            }).join('　'));
        }
        box.innerHTML = parts.join('　·　');
    }

    function detailItem(label, valueHtml) {
        return '<div class="ioc-detail-item"><div class="ioc-detail-item__label">' + esc(label) + '</div>'
            + '<div class="ioc-detail-item__value">' + valueHtml + '</div></div>';
    }

    function renderDetailRow(cveID) {
        const detail = detailCache[cveID];
        if (!detail) {
            return '<tr class="ioc-detail-row"><td colspan="8" class="ioc-detail-cell">' + esc(tt('common.loading', '加载中…')) + '</td></tr>';
        }
        const rec = detail.vulnerability || {};
        const ranges = detail.ranges || [];
        const pocs = detail.pocs || [];
        const grid = detailItem(tt('vulnIntel.colCve', 'CVE'), '<code>' + esc(rec.cve_id || '') + '</code>')
            + detailItem(tt('vulnIntel.colSeverity', '严重度'), severityBadge(rec.severity))
            + detailItem(tt('vulnIntel.colScore', 'CVSS'), esc(rec.cvss_score == null ? '-' : String(rec.cvss_score)))
            + detailItem('EPSS', esc(rec.epss == null ? '-' : (Number(rec.epss) * 100).toFixed(1) + '%'))
            + detailItem(tt('vulnIntel.colSource', '来源'), esc(rec.source || '-'))
            + detailItem(tt('vulnIntel.colPublished', '发布时间'), esc(fmtTime(rec.published_at)));
        const rangeRows = ranges.length
            ? ranges.map(function (r) {
                return '<tr><td>' + esc(r.vendor || '-') + '</td><td><code>' + esc(r.product || '-') + '</code></td>'
                    + '<td>' + esc(formatRange(r)) + '</td>'
                    + '<td>' + esc(r.patched_version || '-') + '</td>'
                    + '<td>' + esc(r.source || '-') + '</td></tr>';
            }).join('')
            : '<tr><td colspan="5" class="ioc-detail-empty">' + esc(tt('vulnIntel.noRanges', '没有结构化版本区间（需要人工判断）')) + '</td></tr>';
        const pocList = pocs.length
            ? pocs.map(function (p) {
                return '<li><a href="' + esc(p.url) + '" target="_blank" rel="noopener noreferrer">' + esc(p.repo || p.url) + '</a>'
                    + ' <span class="page-hint">★ ' + esc(String(p.stars || 0)) + '</span></li>';
            }).join('')
            : '<li class="page-hint">' + esc(tt('vulnIntel.noPocs', '暂无公开 PoC')) + '</li>';
        return '<tr class="ioc-detail-row"><td colspan="8" class="ioc-detail-cell"><div class="ioc-detail">'
            + (rec.title ? '<p class="ioc-detail__note">' + esc(rec.title) + '</p>' : '')
            + '<div class="ioc-detail__grid">' + grid + '</div>'
            + (rec.description ? '<p class="ioc-detail__note" style="margin-top:12px">' + esc(rec.description) + '</p>' : '')
            + '<div class="ioc-detail__hosts"><h4 class="ioc-detail__hosts-title">' + esc(tt('vulnIntel.rangesTitle', '受影响版本区间')) + '</h4>'
            + '<div class="table-container"><table class="data-table ioc-detail-table"><thead><tr>'
            + '<th>' + esc(tt('vulnIntel.colVendor', '厂商')) + '</th><th>' + esc(tt('vulnIntel.colProduct', '组件')) + '</th>'
            + '<th>' + esc(tt('vulnIntel.colRange', '区间')) + '</th><th>' + esc(tt('vulnIntel.colFixed', '修复版本')) + '</th>'
            + '<th>' + esc(tt('vulnIntel.colSource', '来源')) + '</th>'
            + '</tr></thead><tbody>' + rangeRows + '</tbody></table></div></div>'
            + '<div class="ioc-detail__hosts"><h4 class="ioc-detail__hosts-title">' + esc(tt('vulnIntel.pocTitle', '公开 PoC')) + '</h4>'
            + '<ul class="vuln-intel-pocs">' + pocList + '</ul></div>'
            + '</div></td></tr>';
    }

    function formatRange(r) {
        const parts = [];
        if (r.start_including) parts.push('>=' + r.start_including);
        if (r.start_excluding) parts.push('>' + r.start_excluding);
        if (r.end_including) parts.push('<=' + r.end_including);
        if (r.end_excluding) parts.push('<' + r.end_excluding);
        return parts.length ? parts.join(' ') : '-';
    }

    function renderList(items) {
        const tbody = el('vuln-intel-body');
        if (!tbody) return;
        if (!items || !items.length) {
            tbody.innerHTML = '<tr><td colspan="8">' + esc(tt('vulnIntel.empty', '情报库为空：先点「同步情报」拉取公开源')) + '</td></tr>';
            return;
        }
        const rows = [];
        items.forEach(function (r) {
            const expanded = expandedCve === r.cve_id;
            rows.push('<tr>'
                + '<td><code>' + esc(r.cve_id) + '</code></td>'
                + '<td>' + severityBadge(r.severity) + '</td>'
                + '<td>' + esc(r.cvss_score == null ? '-' : String(r.cvss_score)) + '</td>'
                + '<td>' + kevBadge(r.kev) + '</td>'
                + '<td>' + esc(r.epss == null ? '-' : (Number(r.epss) * 100).toFixed(1) + '%') + '</td>'
                + '<td>' + esc(r.source || '-') + '</td>'
                + '<td>' + esc(fmtTime(r.published_at)) + '</td>'
                + '<td><button class="btn-secondary btn-sm" data-require-permission="intel:read" onclick="showVulnIntelDetail(\'' + esc(safeCveId(r.cve_id)) + '\')">'
                + esc(expanded ? tt('vulnIntel.actionCollapse', '收起') : tt('vulnIntel.actionDetail', '详情')) + '</button></td>'
                + '</tr>');
            if (expanded) rows.push(renderDetailRow(r.cve_id));
        });
        tbody.innerHTML = rows.join('');
    }

    async function loadVulnIntel(page) {
        const tbody = el('vuln-intel-body');
        if (tbody) tbody.innerHTML = '<tr><td colspan="8">' + esc(tt('common.loading', '加载中…')) + '</td></tr>';
        try {
            const params = new URLSearchParams();
            const kw = el('vuln-intel-search') ? el('vuln-intel-search').value.trim() : '';
            if (kw) params.set('keyword', kw);
            const sev = el('vuln-intel-severity') ? el('vuln-intel-severity').value : '';
            if (sev) params.set('severity', sev);
            const product = el('vuln-intel-product') ? el('vuln-intel-product').value.trim() : '';
            if (product) params.set('product', product);
            if (el('vuln-intel-kev') && el('vuln-intel-kev').checked) params.set('kev_only', '1');
            params.set('page', String(page || 1));
            currentPage = Number(page) || 1;
            params.set('page_size', String(pageSize));
            const payload = await apiFetchJSON('/api/vuln-intel?' + params.toString());
            intelCache = payload.items || [];
            totalCount = payload.total || 0;
            renderPagination('vuln-intel-pagination');
            renderSummary(payload);
            renderList(intelCache);
        } catch (err) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="8">' + esc(err.message) + '</td></tr>';
        }
    }

    async function showVulnIntelDetail(cveID) {
        if (expandedCve === cveID) {
            expandedCve = '';
            renderList(intelCache);
            return;
        }
        expandedCve = cveID;
        renderList(intelCache);
        if (detailCache[cveID]) return;
        try {
            detailCache[cveID] = await apiFetchJSON('/api/vuln-intel/detail/' + encodeURIComponent(cveID));
        } catch (err) {
            delete detailCache[cveID];
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        }
        renderList(intelCache);
    }

    async function syncVulnIntel() {
        const btn = el('vuln-intel-sync-btn');
        if (btn) { btn.disabled = true; btn.textContent = tt('vulnIntel.syncing', '同步中…'); }
        try {
            const payload = await apiFetchJSON('/api/vuln-intel/sync', { method: 'POST' });
            const s = payload.summary || {};
            if (typeof showNotification === 'function') {
                showNotification(tt('vulnIntel.syncDone', '同步完成') + '：KEV ' + (s.kev || 0)
                    + ' / NVD ' + (s.nvd || 0) + ' / EPSS ' + (s.epss || 0) + ' / GHSA ' + (s.ghsa || 0), 'success');
            }
            await loadVulnIntel();
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = tt('vulnIntel.sync', '同步情报'); }
        }
    }

    window.loadVulnIntel = loadVulnIntel;
    window.showVulnIntelDetail = showVulnIntelDetail;
    window.syncVulnIntel = syncVulnIntel;
    window.initVulnIntelPage = function initVulnIntelPage() { loadVulnIntel(); };

    // ---- 分页：三个列表页共用同一套结构与 skillsPage.* 文案 ----
    let currentPage = 1;
    let pageSize = 20;
    let totalCount = 0;

    function renderPagination(containerId) {
        const box = el(containerId);
        if (!box) return;
        const pages = Math.max(1, Math.ceil(totalCount / pageSize));
        if (currentPage > pages) currentPage = pages;
        const start = totalCount === 0 ? 0 : (currentPage - 1) * pageSize + 1;
        const end = Math.min(currentPage * pageSize, totalCount);
        const disFirst = currentPage <= 1 || totalCount === 0;
        const disLast = currentPage >= pages || totalCount === 0;
        const sizes = [10, 20, 50, 100].map(function (n) {
            return '<option value="' + n + '"' + (n === pageSize ? ' selected' : '') + '>' + n + '</option>';
        }).join('');
        box.innerHTML = '<div class="pagination">'
            + '<div class="pagination-info"><span>' + start + '-' + end + ' / ' + totalCount + '</span>'
            + '<label class="pagination-page-size">' + esc(tt('skillsPage.perPageLabel', '每页显示'))
            + ' <select onchange="vulnIntelChangePageSize(this.value)">' + sizes + '</select></label></div>'
            + '<div class="pagination-controls">'
            + '<button class="btn-secondary" onclick="vulnIntelGotoPage(1)"' + (disFirst ? ' disabled' : '') + '>' + esc(tt('skillsPage.firstPage', '首页')) + '</button>'
            + '<button class="btn-secondary" onclick="vulnIntelGotoPage(' + (currentPage - 1) + ')"' + (disFirst ? ' disabled' : '') + '>' + esc(tt('skillsPage.prevPage', '上一页')) + '</button>'
            + '<span class="pagination-page">' + currentPage + ' / ' + pages + '</span>'
            + '<button class="btn-secondary" onclick="vulnIntelGotoPage(' + (currentPage + 1) + ')"' + (disLast ? ' disabled' : '') + '>' + esc(tt('skillsPage.nextPage', '下一页')) + '</button>'
            + '<button class="btn-secondary" onclick="vulnIntelGotoPage(' + pages + ')"' + (disLast ? ' disabled' : '') + '>' + esc(tt('skillsPage.lastPage', '末页')) + '</button>'
            + '</div></div>';
    }

    function vulnIntelGotoPage(p) {
        const next = Number(p) || 1;
        loadX_(next);
    }

    function vulnIntelChangePageSize(v) {
        pageSize = Number(v) || 20;
        currentPage = 1;
        loadX_(1);
    }

    function loadX_(p) {
        loadVulnIntel(p);
    }

    window.vulnIntelGotoPage = vulnIntelGotoPage;
    window.vulnIntelChangePageSize = vulnIntelChangePageSize;
})();
