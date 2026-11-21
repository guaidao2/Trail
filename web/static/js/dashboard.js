// 仪表盘页面：蓝队态势入口。
//
// 定位：这里不再回答「平台自己忙不忙」（运行中对话 / 工具调用次数 / 成功率 / Token 用量），
// 而是回答「我们的资产现在有多危险」——纳管主机、待处置发现、在野利用命中、IOC 处置状态，
// 加上主机风险 Top 5 与实时事件。数据源与 /wall 攻防态势大屏同一份：GET /api/wall/graph。
//
// 工程约定：
//   - dashboardState 集中保存运行时状态（in-flight controller / 轮询 timer / 上次更新时间 /
//     最近一次成功拿到的 graph，供语言切换后就地重绘）；
//   - 每次 refreshDashboard 入口 abort 上一次请求，避免连点 / 自动轮询触发 race condition；
//   - 自动刷新 30 秒一次；页面切走或标签页隐藏时 tick 内直接跳过（不发请求），
//     重新可见时若已过期则立即补刷一次；
//   - 过期检测：超过 DASHBOARD_STALE_THRESHOLD_MS 未刷新，页头「上次更新」徽章加 .is-stale；
//   - 渲染一律走 DOM API + textContent，不拼 innerHTML：情报标题 / 主机名是外部数据，
//     不能让它们被当成标签解析。

var DASHBOARD_POLL_INTERVAL_MS = 30 * 1000;
var DASHBOARD_STALE_THRESHOLD_MS = 5 * 60 * 1000;
var DASHBOARD_STALE_CHECK_INTERVAL_MS = 15 * 1000;
var DASHBOARD_GRAPH_URL = '/api/wall/graph?events=30';
var DASHBOARD_TOP_HOST_LIMIT = 5;
var DASHBOARD_EVENT_LIMIT = 10;
var DASHBOARD_PLACEHOLDER = '…';

var dashboardState = {
    currentController: null, // 当前正在进行的 fetch 的 AbortController
    pollTimer: null,         // 自动轮询的 setInterval id
    staleTimer: null,        // 过期检查的 setInterval id
    lastUpdatedAt: 0,        // 上次成功刷新的时间戳（ms）
    lastGraph: null,         // 最近一次成功拿到的态势数据（语言切换时重绘用）
    attempted: false         // 是否已发起过至少一次请求（失败后不再每轮闪回 loading）
};

/* ==========================================================================
 * 小工具
 * ========================================================================== */

function dashboardEl(id) {
    return document.getElementById(id);
}

function setDashboardText(id, text) {
    var el = dashboardEl(id);
    if (el) el.textContent = text;
}

// 翻译辅助；找不到时回退到中文兜底文案，避免把内部键名（dashboard.x）显示到界面上。
// 命名为 dashboardT 而非 t，避免覆盖 i18n.js 暴露的 window.t。
function dashboardT(key, opts, fallback) {
    if (typeof window.t === 'function') {
        var v = window.t(key, opts);
        if (v && v !== key) return v;
    }
    return fallback != null ? fallback : key;
}

function dashboardNumber(value) {
    var n = Number(value);
    return isFinite(n) && n > 0 ? n : 0;
}

// 计数展示：0 也要显示成 0（而不是空），大数带千分位
function dashboardCount(value) {
    var n = Math.round(dashboardNumber(value));
    try {
        return n.toLocaleString();
    } catch (_) {
        return String(n);
    }
}

// severity 归一化：后端可能给 critical / crit / severe / moderate 等写法
function dashboardSeverityKey(value) {
    var s = String(value == null ? '' : value).trim().toLowerCase();
    if (s === 'critical' || s === 'crit' || s === 'severe') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium' || s === 'moderate' || s === 'mid') return 'medium';
    if (s === 'low') return 'low';
    return 'info';
}

// 事件时间：当天只给 HH:MM:SS，跨天补上 MM-DD
// SQLite 的 "2026-11-21 10:00:00"（空格分隔、无时区）在 Safari 里 Date.parse 会得到 NaN，
// 这里手动拆开兜底，否则时间列会整列变成占位符。
function dashboardParseTs(value) {
    if (!value) return 0;
    if (typeof value === 'number') return value;
    var s = String(value).trim();
    if (!s) return 0;
    var t = Date.parse(s);
    if (!isNaN(t)) return t;
    var m = s.match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
    if (m) {
        t = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
            Number(m[4]), Number(m[5]), Number(m[6])).getTime();
        if (!isNaN(t)) return t;
    }
    return 0;
}

function dashboardTimeLabel(iso) {
    if (!iso) return '--:--';
    var ts = dashboardParseTs(iso);
    if (!ts) return '--:--';
    var d = new Date(ts);
    function pad(n) { return n < 10 ? '0' + n : String(n); }
    var clock = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    var now = new Date();
    var sameDay = d.getFullYear() === now.getFullYear()
        && d.getMonth() === now.getMonth()
        && d.getDate() === now.getDate();
    if (sameDay) return clock;
    return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + clock;
}

function dashboardHostLabel(node) {
    var name = node && (node.name || node.hostname || node.host_name);
    name = String(name == null ? '' : name).trim();
    if (name) return name;
    var id = node && node.id ? String(node.id) : '';
    if (id.indexOf('host:') === 0) id = id.slice(5);
    return id || dashboardT('dashboard.hostUnknown', null, '未知主机');
}

/* ==========================================================================
 * 渲染：KPI
 * ========================================================================== */

function renderDashboardStats(stats) {
    stats = stats && typeof stats === 'object' ? stats : {};

    var hosts = dashboardNumber(stats.hosts);
    var reachable = dashboardNumber(stats.hosts_reachable);
    var open = dashboardNumber(stats.findings_open);
    var high = dashboardNumber(stats.findings_high);
    var kev = dashboardNumber(stats.kev_hits);

    setDashboardText('dashboard-kpi-hosts', dashboardCount(hosts));
    setDashboardText('dashboard-kpi-hosts-sub',
        dashboardT('dashboard.hostsReachable', { count: reachable }, reachable + ' 台在线'));

    setDashboardText('dashboard-kpi-findings', dashboardCount(open));
    setDashboardText('dashboard-kpi-findings-sub',
        dashboardT('dashboard.findingsHighSub', { count: high }, '其中 ' + high + ' 条高危+'));

    setDashboardText('dashboard-kpi-kev', dashboardCount(kev));
    setDashboardText('dashboard-kpi-kev-sub', kev > 0
        ? dashboardT('dashboard.kevActive', null, '已确认在野利用')
        : dashboardT('dashboard.kevClear', null, '暂无在野利用命中'));
    // 红色只留给「真的有在野利用命中」；为 0 时保持中性色，不做视觉噪音
    var kevCard = dashboardEl('dashboard-metric-kev');
    if (kevCard) {
        if (kev > 0) kevCard.classList.add('is-alert');
        else kevCard.classList.remove('is-alert');
    }

    setDashboardText('dashboard-kpi-ioc', dashboardCount(stats.ioc_total));
    setDashboardText('dashboard-kpi-ioc-observed', dashboardCount(stats.ioc_observed));
    setDashboardText('dashboard-kpi-ioc-confirmed', dashboardCount(stats.ioc_confirmed));
    setDashboardText('dashboard-kpi-ioc-blocked', dashboardCount(stats.ioc_blocked));
}

/* ==========================================================================
 * 渲染：主机风险 Top 5
 * ========================================================================== */

function dashboardTopHosts(nodes) {
    var hosts = (Array.isArray(nodes) ? nodes : []).filter(function (node) {
        return node && node.kind === 'host';
    });
    hosts.sort(function (a, b) {
        return dashboardNumber(b.risk_score) - dashboardNumber(a.risk_score);
    });
    return hosts.slice(0, DASHBOARD_TOP_HOST_LIMIT);
}

function dashboardSeparator() {
    var sep = document.createElement('span');
    sep.className = 'dashboard-risk-sep';
    sep.setAttribute('aria-hidden', 'true');
    sep.textContent = '·';
    return sep;
}

function dashboardRiskChip(label, value) {
    var chip = document.createElement('span');
    chip.className = 'dashboard-risk-chip';
    var key = document.createElement('span');
    key.className = 'dashboard-risk-chip-key';
    key.textContent = label;
    var num = document.createElement('span');
    num.className = 'dashboard-risk-chip-num';
    num.textContent = dashboardCount(value);
    chip.appendChild(key);
    chip.appendChild(num);
    return chip;
}

function renderDashboardHosts(nodes) {
    var list = dashboardEl('dashboard-risk-list');
    if (!list) return;
    var empty = dashboardEl('dashboard-risk-empty');

    var hosts = dashboardTopHosts(nodes);
    list.textContent = '';

    if (!hosts.length) {
        list.hidden = true;
        if (empty) empty.hidden = false;
        return;
    }
    list.hidden = false;
    if (empty) empty.hidden = true;

    hosts.forEach(function (host, index) {
        var risk = Math.max(0, Math.min(100, Math.round(dashboardNumber(host.risk_score))));
        var label = dashboardHostLabel(host);

        var row = document.createElement('div');
        row.className = 'dashboard-risk-row';
        row.setAttribute('data-severity', dashboardSeverityKey(host.severity));
        row.setAttribute('role', 'listitem');

        var rank = document.createElement('span');
        rank.className = 'dashboard-risk-rank';
        rank.setAttribute('aria-hidden', 'true');
        rank.textContent = String(index + 1);

        var name = document.createElement('span');
        name.className = 'dashboard-risk-name';
        name.textContent = label;
        name.title = label;

        var score = document.createElement('span');
        score.className = 'dashboard-risk-score';
        var scoreNum = document.createElement('span');
        scoreNum.className = 'dashboard-risk-score-num';
        scoreNum.textContent = String(risk);
        var scoreUnit = document.createElement('span');
        scoreUnit.className = 'dashboard-risk-score-unit';
        scoreUnit.textContent = dashboardT('dashboard.riskScoreUnit', null, '风险分');
        score.appendChild(scoreNum);
        score.appendChild(scoreUnit);

        var meta = document.createElement('span');
        meta.className = 'dashboard-risk-meta';
        var ip = document.createElement('span');
        ip.className = 'dashboard-risk-ip';
        ip.textContent = host.ip ? String(host.ip) : '—';
        meta.appendChild(ip);
        meta.appendChild(dashboardSeparator());
        meta.appendChild(dashboardRiskChip(
            dashboardT('dashboard.riskFindingsUnit', null, '发现'),
            host.findings_open
        ));
        meta.appendChild(dashboardSeparator());
        meta.appendChild(dashboardRiskChip(
            dashboardT('dashboard.riskHitsUnit', null, '命中'),
            host.ioc_hits
        ));

        var meter = document.createElement('span');
        meter.className = 'dashboard-risk-meter';
        meter.setAttribute('aria-hidden', 'true');
        var fill = document.createElement('span');
        fill.className = 'dashboard-risk-meter-fill';
        fill.style.width = risk + '%';
        meter.appendChild(fill);

        row.appendChild(rank);
        row.appendChild(name);
        row.appendChild(score);
        row.appendChild(meta);
        row.appendChild(meter);
        list.appendChild(row);
    });
}

/* ==========================================================================
 * 渲染：实时事件
 * ========================================================================== */

function dashboardRecentEvents(events) {
    var list = (Array.isArray(events) ? events : []).filter(function (ev) {
        return ev && typeof ev === 'object';
    });
    list.sort(function (a, b) {
        var ta = Date.parse(a.ts || '') || 0;
        var tb = Date.parse(b.ts || '') || 0;
        return tb - ta;
    });
    return list.slice(0, DASHBOARD_EVENT_LIMIT);
}

function renderDashboardEvents(events) {
    var list = dashboardEl('dashboard-live-list');
    if (!list) return;
    var empty = dashboardEl('dashboard-live-empty');

    var rows = dashboardRecentEvents(events);
    list.textContent = '';

    if (!rows.length) {
        list.hidden = true;
        if (empty) empty.hidden = false;
        return;
    }
    list.hidden = false;
    if (empty) empty.hidden = true;

    rows.forEach(function (ev) {
        var row = document.createElement('div');
        row.className = 'dashboard-live-row';
        row.setAttribute('data-severity', dashboardSeverityKey(ev.severity));

        var time = document.createElement('span');
        time.className = 'dashboard-live-time';
        time.textContent = dashboardTimeLabel(ev.ts);

        var host = document.createElement('span');
        host.className = 'dashboard-live-host';
        host.textContent = String(ev.host || ev.host_name || dashboardT('dashboard.hostUnknown', null, '未知主机'));

        var title = document.createElement('span');
        title.className = 'dashboard-live-title';
        title.textContent = String(ev.title || ev.value || dashboardT('dashboard.eventUntitled', null, '事件'));
        title.title = title.textContent;

        row.appendChild(time);
        row.appendChild(host);
        row.appendChild(title);
        list.appendChild(row);
    });
}

/* ==========================================================================
 * 渲染：整页状态
 * ========================================================================== */

function renderDashboardGraph(graph) {
    var g = graph && typeof graph === 'object' ? graph : {};
    renderDashboardStats(g.stats);
    renderDashboardHosts(g.nodes);
    renderDashboardEvents(g.events);
}

function renderDashboardLoading() {
    ['dashboard-kpi-hosts', 'dashboard-kpi-findings', 'dashboard-kpi-kev', 'dashboard-kpi-ioc'].forEach(function (id) {
        setDashboardText(id, DASHBOARD_PLACEHOLDER);
    });
    [
        'dashboard-kpi-hosts-sub', 'dashboard-kpi-findings-sub', 'dashboard-kpi-kev-sub',
        'dashboard-kpi-ioc-observed', 'dashboard-kpi-ioc-confirmed', 'dashboard-kpi-ioc-blocked'
    ].forEach(function (id) {
        setDashboardText(id, DASHBOARD_PLACEHOLDER);
    });
    var kevCard = dashboardEl('dashboard-metric-kev');
    if (kevCard) kevCard.classList.remove('is-alert');
}

// 首屏就拿不到数据时的状态：显示破折号 + 两块面板的空态，而不是一直转圈
function renderDashboardUnavailable() {
    ['dashboard-kpi-hosts', 'dashboard-kpi-findings', 'dashboard-kpi-kev', 'dashboard-kpi-ioc'].forEach(function (id) {
        setDashboardText(id, '—');
    });
    [
        'dashboard-kpi-hosts-sub', 'dashboard-kpi-findings-sub', 'dashboard-kpi-kev-sub',
        'dashboard-kpi-ioc-observed', 'dashboard-kpi-ioc-confirmed', 'dashboard-kpi-ioc-blocked'
    ].forEach(function (id) {
        setDashboardText(id, '—');
    });
    renderDashboardHosts([]);
    renderDashboardEvents([]);
}

function showDashboardError() {
    var box = dashboardEl('dashboard-load-error');
    if (box) box.hidden = false;
}

function hideDashboardError() {
    var box = dashboardEl('dashboard-load-error');
    if (box) box.hidden = true;
}

/* ==========================================================================
 * 页头：最后更新时间 / 过期徽章
 * ========================================================================== */

function updateDashboardLastUpdated() {
    dashboardState.lastUpdatedAt = Date.now();
    var pad = function (n) { return n < 10 ? '0' + n : String(n); };
    var el = dashboardEl('dashboard-last-updated-time');
    if (el) {
        var d = new Date();
        el.textContent = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }
    var wrap = dashboardEl('dashboard-last-updated');
    if (wrap) {
        wrap.classList.remove('is-stale', 'is-flash');
        void wrap.offsetWidth; // 触发 reflow，让闪烁动画可以重播
        wrap.classList.add('is-flash');
    }
    var stale = dashboardEl('dashboard-last-updated-stale');
    if (stale) stale.hidden = true;
}

function checkDashboardStale() {
    if (!dashboardState.lastUpdatedAt) return;
    var wrap = dashboardEl('dashboard-last-updated');
    if (!wrap) return;
    var stale = dashboardEl('dashboard-last-updated-stale');
    var ageMs = Date.now() - dashboardState.lastUpdatedAt;
    if (ageMs > DASHBOARD_STALE_THRESHOLD_MS) {
        wrap.classList.add('is-stale');
        if (stale) stale.hidden = false;
    } else {
        wrap.classList.remove('is-stale');
        if (stale) stale.hidden = true;
    }
}

/* ==========================================================================
 * 数据拉取
 * ========================================================================== */

// 走 apiFetch（带 Bearer / 401 处理）；退化环境下用同源 fetch，保证 cookie 鉴权也能用
function dashboardRequestGraph(signal) {
    if (typeof apiFetch === 'function') {
        return apiFetch(DASHBOARD_GRAPH_URL, { signal: signal });
    }
    return fetch(DASHBOARD_GRAPH_URL, { credentials: 'same-origin', signal: signal });
}

async function refreshDashboard() {
    // 只有首屏才闪成占位；自动轮询时静默替换，避免每 30 秒白一下
    if (!dashboardState.lastUpdatedAt && !dashboardState.attempted) renderDashboardLoading();
    dashboardState.attempted = true;

    if (dashboardState.currentController) {
        try { dashboardState.currentController.abort(); } catch (_) { /* ignore */ }
    }
    var controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    dashboardState.currentController = controller;
    var signal = controller ? controller.signal : undefined;

    try {
        var response = await dashboardRequestGraph(signal);
        if (controller && controller.signal.aborted) return;
        if (!response || !response.ok) throw new Error('dashboard graph request failed');
        var graph = await response.json();
        if (controller && controller.signal.aborted) return;
        if (!graph || typeof graph !== 'object') throw new Error('dashboard graph payload invalid');

        dashboardState.lastGraph = graph;
        renderDashboardGraph(graph);
        hideDashboardError();
        updateDashboardLastUpdated();
    } catch (err) {
        if (controller && controller.signal.aborted) return;
        // 拉不到数据时不清空已有态势，只在顶部挂一条失败提示；
        // 首屏就没拿到数据才退化成空态，避免永远停在「…」
        showDashboardError();
        if (!dashboardState.lastUpdatedAt) renderDashboardUnavailable();
    } finally {
        if (dashboardState.currentController === controller) dashboardState.currentController = null;
        startDashboardAutoRefresh();
    }
}

/* ==========================================================================
 * 自动刷新
 * ========================================================================== */

// 30 秒一轮；页面切走 / 标签页隐藏都在 tick 内跳过（等价于暂停，且不留请求）
function startDashboardAutoRefresh() {
    if (dashboardState.pollTimer) return;
    dashboardState.pollTimer = setInterval(function () {
        try {
            var page = dashboardEl('page-dashboard');
            if (!page || !page.classList.contains('active')) return;
            if (typeof document !== 'undefined' && document.hidden) return;
            refreshDashboard();
        } catch (e) {
            console.warn('dashboard auto refresh tick failed', e);
        }
    }, DASHBOARD_POLL_INTERVAL_MS);

    if (!dashboardState.staleTimer) {
        dashboardState.staleTimer = setInterval(checkDashboardStale, DASHBOARD_STALE_CHECK_INTERVAL_MS);
    }
}

/* ==========================================================================
 * 全局事件
 * ========================================================================== */

// 语言切换：KPI 副标 / 空态 / 主机行里的单位文案都是 JS 渲染的，
// applyTranslations 不会重绘它们，这里用最近一次数据就地重绘（没数据才重新拉）。
document.addEventListener('languagechange', function () {
    try {
        var page = dashboardEl('page-dashboard');
        if (!page || !page.classList.contains('active')) return;
        if (dashboardState.lastGraph) renderDashboardGraph(dashboardState.lastGraph);
        else refreshDashboard();
    } catch (e) {
        console.warn('dashboard languagechange refresh failed', e);
    }
});

// 页面可见性：从其他 tab 切回时，超过半个轮询周期就立刻补刷一次，
// 避免后台标签页停留几小时回来时数据还是旧的，又不至于每次切回都打接口。
document.addEventListener('visibilitychange', function () {
    var page = dashboardEl('page-dashboard');
    if (!page || !page.classList.contains('active')) return;
    if (typeof document !== 'undefined' && document.hidden) return;
    var ageMs = Date.now() - (dashboardState.lastUpdatedAt || 0);
    if (!dashboardState.lastUpdatedAt || ageMs >= DASHBOARD_POLL_INTERVAL_MS / 2) {
        try { refreshDashboard(); } catch (_) { /* ignore */ }
    } else {
        checkDashboardStale();
    }
});
