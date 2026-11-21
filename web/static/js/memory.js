/*
 * Agent 记忆页面：三级记忆（关键 / 长期 / 短期）的查看、筛选、新增、编辑、删除。
 *
 * 数据与 Agent 的 memory_* 工具共用同一张表；这里给人一个修正与清理的入口。
 */
(function () {
    let memoryCache = [];
    let currentMemoryId = '';

    function el(id) {
        return document.getElementById(id);
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
        if (!res.ok) {
            throw new Error(data.error || ('请求失败 (' + res.status + ')'));
        }
        return data;
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

    const TIER_LABEL = {
        critical: 'memory.tierCritical',
        long_term: 'memory.tierLongTerm',
        short_term: 'memory.tierShortTerm',
    };
    const TIER_COLOR = {
        critical: '#dc2626',
        long_term: '#2563eb',
        short_term: '#0891b2',
    };
    const SCOPE_LABEL = {
        global: 'memory.scopeGlobal',
        host: 'memory.scopeHost',
        user: 'memory.scopeUser',
    };

    function tierLabel(tier) {
        const key = TIER_LABEL[String(tier || 'long_term')];
        return key ? tt(key, String(tier)) : String(tier || '');
    }

    function tierBadge(tier) {
        const t = String(tier || 'long_term');
        return '<span style="display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;color:#fff;background:'
            + (TIER_COLOR[t] || '#64748b') + '">' + esc(tierLabel(t)) + '</span>';
    }

    function renderSummary(payload) {
        const box = el('memory-summary');
        if (!box) return;
        const by = payload.by_tier || {};
        const order = ['critical', 'long_term', 'short_term'];
        const parts = order
            .filter(function (k) { return by[k]; })
            .map(function (k) { return esc(tierLabel(k)) + ' <strong>' + esc(String(by[k])) + '</strong>'; });
        box.innerHTML = esc(tt('memory.totalPrefix', '共')) + ' <strong>' + esc(String(payload.total || 0)) + '</strong> '
            + esc(tt('memory.totalSuffix', '条')) + (parts.length ? '　' + parts.join('　') : '');
    }

    function renderList(items) {
        const tbody = el('memory-body');
        if (!tbody) return;
        if (!items || !items.length) {
            tbody.innerHTML = '<tr><td colspan="7">' + esc(tt('memory.empty', '还没有记忆')) + '</td></tr>';
            return;
        }
        tbody.innerHTML = items.map(function (m) {
            const scopeKey = SCOPE_LABEL[String(m.scope || 'global')];
            const scopeText = (scopeKey ? tt(scopeKey, m.scope) : String(m.scope || ''))
                + (m.host_id ? ' · ' + m.host_id : '');
            const content = String(m.content || '');
            const short = content.length > 140 ? content.slice(0, 140) + '…' : content;
            const actions = '<button class="btn-secondary btn-sm" data-require-permission="memory:write" onclick="editMemory(\'' + esc(m.id) + '\')">'
                + esc(tt('common.edit', '编辑')) + '</button> '
                + '<button class="btn-danger btn-sm" data-require-permission="memory:write" onclick="deleteMemory(\'' + esc(m.id) + '\')">'
                + esc(tt('common.delete', '删除')) + '</button>';
            return '<tr>'
                + '<td>' + tierBadge(m.tier) + '</td>'
                + '<td><code>' + esc(m.key) + '</code></td>'
                + '<td title="' + esc(content) + '">' + esc(short) + '</td>'
                + '<td>' + esc(scopeText) + '</td>'
                + '<td>' + esc(String(m.hit_count || 0)) + '</td>'
                + '<td>' + esc(fmtTime(m.updated_at)) + '</td>'
                + '<td>' + actions + '</td>'
                + '</tr>';
        }).join('');
    }

    async function loadMemories(page) {
        const tbody = el('memory-body');
        if (tbody) tbody.innerHTML = '<tr><td colspan="7">' + esc(tt('common.loading', '加载中…')) + '</td></tr>';
        try {
            const params = new URLSearchParams();
            const kw = el('memory-search') ? el('memory-search').value.trim() : '';
            if (kw) params.set('keyword', kw);
            const tier = el('memory-tier-filter') ? el('memory-tier-filter').value : '';
            if (tier) params.set('tier', tier);
            const scope = el('memory-scope-filter') ? el('memory-scope-filter').value : '';
            if (scope) params.set('scope', scope);
            params.set('page', String(page || 1));
            currentPage = Number(page) || 1;
            params.set('page_size', String(pageSize));
            const payload = await apiFetchJSON('/api/memory?' + params.toString());
            memoryCache = payload.items || [];
            totalCount = payload.total || 0;
            renderPagination('memory-pagination');
            renderSummary(payload);
            renderList(memoryCache);
        } catch (err) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="7">' + esc(err.message) + '</td></tr>';
        }
    }

    function fillEditor(m) {
        if (el('memory-form-key')) el('memory-form-key').value = m ? m.key || '' : '';
        if (el('memory-form-tier')) el('memory-form-tier').value = m ? m.tier || 'long_term' : 'long_term';
        if (el('memory-form-scope')) el('memory-form-scope').value = m ? m.scope || 'global' : 'global';
        if (el('memory-form-host')) el('memory-form-host').value = m ? m.host_id || '' : '';
        if (el('memory-form-tags')) el('memory-form-tags').value = m ? m.tags || '' : '';
        if (el('memory-form-content')) el('memory-form-content').value = m ? m.content || '' : '';
        if (el('memory-form-ttl')) el('memory-form-ttl').value = 30;
    }

    function openMemoryEditor() {
        currentMemoryId = '';
        fillEditor(null);
        const title = el('memory-edit-title');
        if (title) title.textContent = tt('memory.add', '新增记忆');
        const modal = el('memory-edit-modal');
        if (modal) modal.style.display = 'flex';
        const key = el('memory-form-key');
        if (key && typeof key.focus === 'function') key.focus();
    }

    function editMemory(id) {
        const m = memoryCache.find(function (x) { return x.id === id; });
        if (!m) return;
        currentMemoryId = id;
        fillEditor(m);
        const title = el('memory-edit-title');
        if (title) title.textContent = tt('common.edit', '编辑') + ' · ' + m.key;
        const modal = el('memory-edit-modal');
        if (modal) modal.style.display = 'flex';
    }

    function closeMemoryEditor() {
        const modal = el('memory-edit-modal');
        if (modal) modal.style.display = 'none';
        currentMemoryId = '';
    }

    async function saveMemory() {
        const key = el('memory-form-key') ? el('memory-form-key').value.trim() : '';
        const content = el('memory-form-content') ? el('memory-form-content').value.trim() : '';
        if (!key || !content) {
            if (typeof showNotification === 'function') showNotification(tt('memory.keyRequired', '键与内容都不能为空'), 'error');
            return;
        }
        try {
            await apiFetchJSON('/api/memory', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    key: key,
                    content: content,
                    tier: el('memory-form-tier') ? el('memory-form-tier').value : 'long_term',
                    scope: el('memory-form-scope') ? el('memory-form-scope').value : 'global',
                    host_id: el('memory-form-host') ? el('memory-form-host').value.trim() : '',
                    tags: el('memory-form-tags') ? el('memory-form-tags').value.trim() : '',
                    ttl_days: el('memory-form-ttl') ? Number(el('memory-form-ttl').value) : 30,
                }),
            });
            closeMemoryEditor();
            await loadMemories();
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        }
    }

    async function deleteMemory(id) {
        if (typeof window.confirm === 'function' && !window.confirm(tt('memory.deleteConfirm', '删除这条记忆？'))) {
            return;
        }
        try {
            await apiFetchJSON('/api/memory/' + encodeURIComponent(id), { method: 'DELETE' });
            await loadMemories();
        } catch (err) {
            if (typeof showNotification === 'function') showNotification(err.message, 'error');
        }
    }

    window.loadMemories = loadMemories;
    window.openMemoryEditor = openMemoryEditor;
    window.editMemory = editMemory;
    window.closeMemoryEditor = closeMemoryEditor;
    window.saveMemory = saveMemory;
    window.deleteMemory = deleteMemory;
    window.initMemoryPage = function initMemoryPage() {
        loadMemories();
    };

    // ---- 分页：与 skillsPage.* 文案保持一致 ----
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
            + ' <select onchange="memoryChangePageSize(this.value)">' + sizes + '</select></label></div>'
            + '<div class="pagination-controls">'
            + '<button class="btn-secondary" onclick="memoryGotoPage(1)"' + (disFirst ? ' disabled' : '') + '>' + esc(tt('skillsPage.firstPage', '首页')) + '</button>'
            + '<button class="btn-secondary" onclick="memoryGotoPage(' + (currentPage - 1) + ')"' + (disFirst ? ' disabled' : '') + '>' + esc(tt('skillsPage.prevPage', '上一页')) + '</button>'
            + '<span class="pagination-page">' + currentPage + ' / ' + pages + '</span>'
            + '<button class="btn-secondary" onclick="memoryGotoPage(' + (currentPage + 1) + ')"' + (disLast ? ' disabled' : '') + '>' + esc(tt('skillsPage.nextPage', '下一页')) + '</button>'
            + '<button class="btn-secondary" onclick="memoryGotoPage(' + pages + ')"' + (disLast ? ' disabled' : '') + '>' + esc(tt('skillsPage.lastPage', '末页')) + '</button>'
            + '</div></div>';
    }

    function memoryGotoPage(p) {
        loadMemories(Number(p) || 1);
    }

    function memoryChangePageSize(v) {
        pageSize = Number(v) || 20;
        currentPage = 1;
        loadMemories(1);
    }

    window.memoryGotoPage = memoryGotoPage;
    window.memoryChangePageSize = memoryChangePageSize;
})();
