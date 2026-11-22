/*
 * 威胁情报页面：源健康、单指标聚合查询、订阅 feed 浏览与同步。
 *
 * 这个页面展示的是「外部源观测到什么」，不是「我们认定什么」。
 * 想做封禁或状态流转，去 IOC 情报页；两边数据是分开的，别混着理解。
 */
(function () {
    // 分页状态命名与其他页面（ioc.js / vuln-intel.js / memory.js）保持一致，
    // 方便对照，也避免以后有人把这套组件抽成公共模块时还要改名。
    let currentPage = 1;
    let pageSize = 20;
    let totalCount = 0;
    let lastQuery = null;

    function el(id) {
        return document.getElementById(id);
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    async function apiFetchJSON(url, options) {
        const res = await apiFetch(url, options);
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok) {
            throw new Error(data.error || ('请求失败 (' + res.status + ')'));
        }
        return data;
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

    // 判定值到展示文案与颜色。exposure 不是"恶意"，单独一档，别混进 suspicious。
    const VERDICT_META = {
        malicious:  { key: 'threatIntel.verdictMalicious',  fallback: '恶意',   cls: 'is-danger' },
        suspicious: { key: 'threatIntel.verdictSuspicious', fallback: '可疑',   cls: 'is-warn' },
        clean:      { key: 'threatIntel.verdictClean',      fallback: '未见异常', cls: 'is-ok' },
        exposure:   { key: 'threatIntel.verdictExposure',   fallback: '暴露面', cls: 'is-info' },
        unknown:    { key: 'threatIntel.verdictUnknown',    fallback: '未知',   cls: 'is-muted' }
    };

    function verdictBadge(verdict) {
        const meta = VERDICT_META[verdict] || VERDICT_META.unknown;
        return '<span class="threat-verdict ' + meta.cls + '">' + esc(tt(meta.key, meta.fallback)) + '</span>';
    }

    // ---------- 源健康 ----------

    async function loadThreatSources() {
        const box = el('threat-sources');
        if (!box) return;
        try {
            const data = await apiFetchJSON('/api/threat-intel/sources');
            if (!data.enabled) {
                box.innerHTML = '<span class="is-muted">' + esc(tt('threatIntel.disabled', '威胁情报模块未启用')) + '</span>';
                return;
            }
            const counts = {};
            (data.feed_counts || []).forEach(function (c) { counts[c.source] = c.count; });
            const items = data.items || [];
            if (!items.length) {
                box.innerHTML = '<span class="is-muted">' + esc(tt('threatIntel.noSources', '还没有注册任何情报源')) + '</span>';
                return;
            }
            box.innerHTML = items.map(function (s) {
                const parts = [];
                parts.push('<span class="threat-source-name">' + esc(s.source) + '</span>');
                parts.push('<span class="threat-source-mode">' +
                    esc(s.mode === 'feed'
                        ? tt('threatIntel.modeFeed', '订阅')
                        : tt('threatIntel.modeLookup', '查询')) + '</span>');
                if (!s.enabled) {
                    parts.push('<span class="threat-source-off">' + esc(tt('threatIntel.sourceOff', '已停用')) + '</span>');
                }
                if (s.requires_key) {
                    parts.push('<span class="threat-source-key">' + esc(tt('threatIntel.needKey', '需 Key')) + '</span>');
                }
                if (s.mode === 'feed') {
                    parts.push('<span class="threat-source-count">' +
                        esc((counts[s.source] || 0) + ' ' + tt('threatIntel.entries', '条')) + '</span>');
                } else if (s.daily_quota > 0) {
                    parts.push('<span class="threat-source-quota">' +
                        esc(s.quota_used + '/' + s.daily_quota) + '</span>');
                }
                const tip = s.last_error
                    ? s.last_error
                    : (s.last_ok_at ? tt('threatIntel.lastOk', '最近成功') + ' ' + fmtTime(s.last_ok_at) : '');
                return '<span class="threat-source-chip' + (s.last_error ? ' has-error' : '') + '" title="' + esc(tip) + '">' +
                    parts.join('') + '</span>';
            }).join('');
        } catch (err) {
            box.innerHTML = '<span class="is-muted">' + esc(err.message) + '</span>';
        }
    }

    // ---------- 单指标查询 ----------

    async function runThreatQuery() {
        const valueInput = el('threat-query-value');
        const typeInput = el('threat-query-type');
        const out = el('threat-query-result');
        if (!valueInput || !out) return;
        const value = (valueInput.value || '').trim();
        if (!value) {
            out.innerHTML = '<div class="is-muted">' + esc(tt('threatIntel.needValue', '请输入要查询的指标')) + '</div>';
            return;
        }
        const type = (typeInput && typeInput.value) || 'ip';
        out.innerHTML = '<div class="is-muted">' + esc(tt('common.loading', '加载中…')) + '</div>';
        try {
            const data = await apiFetchJSON('/api/threat-intel/query?type=' + encodeURIComponent(type) +
                '&value=' + encodeURIComponent(value));
            lastQuery = data;
            renderQueryResult(data);
        } catch (err) {
            out.innerHTML = '<div class="threat-error">' + esc(err.message) + '</div>';
        }
    }

    function renderQueryResult(data) {
        const out = el('threat-query-result');
        if (!out) return;
        const results = data.results || [];
        const feedHits = data.feed_hits || [];

        let html = '';
        html += '<div class="threat-result-head">';
        html += '<span class="threat-result-value">' + esc(data.normalized || data.value) + '</span>';
        html += verdictBadge(data.overall_verdict);
        html += '<span class="is-muted">' + esc(tt('threatIntel.overall', '综合判定')) + '</span>';
        html += '</div>';

        if (data.note) {
            html += '<div class="threat-result-note">' + esc(data.note) + '</div>';
        }

        if (feedHits.length) {
            html += '<div class="threat-result-section">';
            html += '<h4>' + esc(tt('threatIntel.feedHits', '命中的订阅条目')) + '</h4>';
            html += '<div class="threat-feed-hits">';
            feedHits.forEach(function (h) {
                html += '<div class="threat-feed-hit">';
                html += '<span class="threat-feed-source">' + esc(h.source) + '</span>';
                if (h.category) html += '<span class="threat-feed-cat">' + esc(h.category) + '</span>';
                if (h.malware) html += '<span class="threat-feed-malware">' + esc(h.malware) + '</span>';
                html += '</div>';
            });
            html += '</div></div>';
        }

        // 信誉判定与暴露面分两栏：把"开着 80 端口"和"被判定恶意"排在一起会误导。
        const reputation = results.filter(function (r) { return r.category === 'reputation'; });
        const exposure = results.filter(function (r) { return r.category !== 'reputation'; });

        if (reputation.length) {
            html += '<div class="threat-result-section">';
            html += '<h4>' + esc(tt('threatIntel.reputationSection', '信誉判定')) + '</h4>';
            html += reputation.map(renderResultCard).join('');
            html += '</div>';
        }
        if (exposure.length) {
            html += '<div class="threat-result-section">';
            html += '<h4>' + esc(tt('threatIntel.exposureSection', '暴露面观测')) + '</h4>';
            html += exposure.map(renderResultCard).join('');
            html += '</div>';
        }
        if (!results.length && !feedHits.length) {
            html += '<div class="is-muted">' + esc(tt('threatIntel.noResult', '没有任何源返回结果')) + '</div>';
        }

        if ((data.skipped || []).length) {
            html += '<div class="threat-skipped"><span class="is-muted">' +
                esc(tt('threatIntel.skipped', '跳过的源')) + '：</span>' +
                data.skipped.map(function (s) { return '<span class="threat-skipped-item">' + esc(s) + '</span>'; }).join('') +
                '</div>';
        }

        out.innerHTML = html;
    }

    function renderResultCard(r) {
        let html = '<div class="threat-result-card">';
        html += '<div class="threat-result-card-head">';
        html += '<span class="threat-result-source">' + esc(r.source) + '</span>';
        html += verdictBadge(r.verdict);
        if (r.cached) {
            html += '<span class="threat-cached">' + esc(tt('threatIntel.cached', '缓存')) + '</span>';
        }
        if (r.http_status && r.http_status !== 200) {
            html += '<span class="is-muted">HTTP ' + esc(r.http_status) + '</span>';
        }
        html += '</div>';
        if (r.summary) {
            html += '<div class="threat-result-summary">' + esc(r.summary) + '</div>';
        }
        if ((r.tags || []).length) {
            html += '<div class="threat-result-tags">' +
                r.tags.map(function (tag) { return '<span class="threat-tag">' + esc(tag) + '</span>'; }).join('') +
                '</div>';
        }
        if (r.expires_at) {
            html += '<div class="threat-result-expire is-muted">' +
                esc(tt('threatIntel.expires', '缓存有效期')) + ' ' + esc(fmtTime(r.expires_at)) + '</div>';
        }
        // 采纳按钮：外部观测要进 IOC 库，必须有人显式点这一下。
        // 采纳走 POST /threat-intel/adopt，路由要求 threatintel:write，
        // handler 里还要 ioc:write；两者缺一个都会 403，所以按钮要同时满足。
        const canAdopt = (typeof window.hasPermission !== 'function') ||
            (window.hasPermission('ioc:write') && window.hasPermission('threatintel:write'));
        if (canAdopt && r.category === 'reputation') {
            html += '<div class="threat-result-actions">' +
                '<button class="btn-secondary btn-sm" onclick="adoptThreatToIOC(this)"' +
                ' data-source="' + esc(r.source) + '"' +
                ' data-verdict="' + esc(r.verdict) + '"' +
                ' data-summary="' + esc(r.summary || '') + '">' +
                esc(tt('threatIntel.adopt', '采纳为 IOC')) + '</button></div>';
        }
        return html + '</div>';
    }

    // 把一条外部观测写成 IOC。状态固定为 observed，由人来决定后续升格。
    async function adoptThreatToIOC(btn) {
        if (!lastQuery) return;
        const source = btn.getAttribute('data-source') || '';
        const verdict = btn.getAttribute('data-verdict') || '';
        const summary = btn.getAttribute('data-summary') || '';
        btn.disabled = true;
        try {
            const data = await apiFetchJSON('/api/threat-intel/adopt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    type: lastQuery.type,
                    value: lastQuery.value,
                    source: source,
                    verdict: verdict,
                    summary: summary
                })
            });
            if (typeof showNotification === 'function') {
                showNotification(
                    data.created
                        ? tt('threatIntel.adoptCreated', '已写入 IOC 库（状态：观察）')
                        : tt('threatIntel.adoptUpdated', 'IOC 库已有该指标，已合并'),
                    'success'
                );
            }
            btn.textContent = tt('threatIntel.adopted', '已采纳');
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
            btn.disabled = false;
        }
    }

    // ---------- 订阅 feed ----------

    async function loadThreatFeed(page) {
        if (page) currentPage = Number(page) || 1;
        const body = el('threat-feed-body');
        if (!body) return;
        body.innerHTML = '<tr><td colspan="6" class="is-muted">' + esc(tt('common.loading', '加载中…')) + '</td></tr>';

        const params = new URLSearchParams();
        params.set('page', String(currentPage));
        params.set('page_size', String(pageSize));
        const keyword = el('threat-feed-search');
        const source = el('threat-feed-source');
        const type = el('threat-feed-type');
        if (keyword && keyword.value.trim()) params.set('keyword', keyword.value.trim());
        if (source && source.value) params.set('source', source.value);
        if (type && type.value) params.set('type', type.value);

        try {
            const data = await apiFetchJSON('/api/threat-intel/feed?' + params.toString());
            renderFeed(data);
        } catch (err) {
            body.innerHTML = '<tr><td colspan="6" class="threat-error">' + esc(err.message) + '</td></tr>';
        }
    }

    function renderFeed(data) {
        const body = el('threat-feed-body');
        if (!body) return;
        const items = data.items || [];
        totalCount = Number(data.total) || 0;
        if (!items.length) {
            body.innerHTML = '<tr><td colspan="6" class="is-muted">' +
                esc(tt('threatIntel.feedEmpty', '还没有订阅数据，点右上角同步试试')) + '</td></tr>';
        } else {
            body.innerHTML = items.map(function (it) {
                return '<tr>' +
                    '<td class="threat-feed-value">' + esc(it.normalized) + '</td>' +
                    '<td>' + esc(it.indicator_type) + '</td>' +
                    '<td>' + esc(it.source) + '</td>' +
                    '<td>' + esc(it.category || '-') + '</td>' +
                    '<td>' + esc(it.malware || '-') + '</td>' +
                    '<td>' + esc(fmtTime(it.last_seen || it.fetched_at)) + '</td>' +
                    '</tr>';
            }).join('');
        }
        renderFeedPagination();
    }

    // ---- 分页：与 IOC / 漏洞情报 / 记忆页同一套组件与文案 ----
    // 自己搓的"上一页/下一页"跟别处不一致，用户一眼就能看出是拼出来的，
    // 所以直接用同一组 class、同样的 skillsPage.* 文案与每页条数选择。
    function renderFeedPagination() {
        const box = el('threat-feed-pagination');
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
            + ' <select onchange="threatIntelChangePageSize(this.value)">' + sizes + '</select></label></div>'
            + '<div class="pagination-controls">'
            + '<button class="btn-secondary" onclick="threatIntelGotoPage(1)"' + (disFirst ? ' disabled' : '') + '>' + esc(tt('skillsPage.firstPage', '首页')) + '</button>'
            + '<button class="btn-secondary" onclick="threatIntelGotoPage(' + (currentPage - 1) + ')"' + (disFirst ? ' disabled' : '') + '>' + esc(tt('skillsPage.prevPage', '上一页')) + '</button>'
            + '<span class="pagination-page">' + currentPage + ' / ' + pages + '</span>'
            + '<button class="btn-secondary" onclick="threatIntelGotoPage(' + (currentPage + 1) + ')"' + (disLast ? ' disabled' : '') + '>' + esc(tt('skillsPage.nextPage', '下一页')) + '</button>'
            + '<button class="btn-secondary" onclick="threatIntelGotoPage(' + pages + ')"' + (disLast ? ' disabled' : '') + '>' + esc(tt('skillsPage.lastPage', '末页')) + '</button>'
            + '</div></div>';
    }

    function threatIntelGotoPage(p) {
        loadThreatFeed(Number(p) || 1);
    }

    function threatIntelChangePageSize(v) {
        pageSize = Number(v) || 20;
        currentPage = 1;
        loadThreatFeed(1);
    }

    window.threatIntelGotoPage = threatIntelGotoPage;
    window.threatIntelChangePageSize = threatIntelChangePageSize;

    async function syncThreatFeed() {
        const btn = el('threat-sync-btn');
        if (btn) { btn.disabled = true; btn.dataset.originalText = btn.textContent; btn.textContent = tt('threatIntel.syncing', '同步中…'); }
        try {
            const data = await apiFetchJSON('/api/threat-intel/feed/sync', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: '{}'
            });
            const synced = data.synced || {};
            const names = Object.keys(synced);
            let msg = names.length
                ? names.map(function (n) { return n + ' ' + synced[n]; }).join('，')
                : tt('threatIntel.nothingSynced', '没有可同步的源（可能都缺 Key）');
            if ((data.errors || []).length) {
                msg += '；' + tt('threatIntel.syncErrors', '部分失败') + '：' + data.errors.join('；');
            }
            if (typeof showNotification === 'function') {
                showNotification(msg, (data.errors || []).length ? 'warning' : 'success');
            }
            await loadThreatSources();
            await loadThreatFeed(1);
            await refreshFeedSourceOptions();
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        } finally {
            if (btn) { btn.disabled = false; btn.textContent = btn.dataset.originalText || tt('threatIntel.sync', '同步订阅源'); }
        }
    }

    // 订阅源下拉选项跟着源清单走，避免硬编码源名。
    async function refreshFeedSourceOptions() {
        const sel = el('threat-feed-source');
        if (!sel) return;
        try {
            const data = await apiFetchJSON('/api/threat-intel/sources');
            const feeds = (data.items || []).filter(function (s) { return s.mode === 'feed'; });
            const current = sel.value;
            sel.innerHTML = '<option value="">' + esc(tt('threatIntel.allSources', '全部来源')) + '</option>' +
                feeds.map(function (s) {
                    return '<option value="' + esc(s.source) + '">' + esc(s.source) + '</option>';
                }).join('');
            if (current) sel.value = current;
        } catch (e) { /* 选项加载失败不阻塞主流程 */ }
    }

    function initThreatIntelPage() {
        loadThreatSources();
        refreshFeedSourceOptions();
        loadThreatFeed(1);
    }

    window.initThreatIntelPage = initThreatIntelPage;
    window.loadThreatSources = loadThreatSources;
    window.loadThreatFeed = loadThreatFeed;
    window.runThreatQuery = runThreatQuery;
    window.syncThreatFeed = syncThreatFeed;
    window.adoptThreatToIOC = adoptThreatToIOC;
})();
