/*
 * 攻防态势大屏（AWD 沙盘）—— three.js 场景 + 图数据 + 全息动画。
 *
 * 设计取舍（写在这里，改代码前先看）：
 * 1) 布局完全自己做：主机走简化 3D 力导向（同组吸引 / 异组斥力 / 最小间距 / 球壳约束），
 *    IOC 只是"挂在命中的主机旁边"的小节点，不参与斥力，所以代价恒定。
 * 2) 上千节点时的性能：只有 risk 最高的 MAX_ACTIVE_HOSTS 台主机参与力导向（O(n^2)，
 *    n<=160），其余主机固定在球壳的 fibonacci 格点上，位置永不变，也不参与任何两两计算。
 *    两两计算的规模因此与总节点数无关。
 * 3) 渲染只用 3 个 InstancedMesh（主机球 / 情报八面体 / 主机光环）+ 1 个 LineSegments
 *    （全部关系线）+ 1 个 Points（粒子流），draw call 恒定，与节点数量无关。
 * 4) 文字一律不进 3D：统计、Top 风险、事件、tooltip 都是 HTML 覆盖层，中文不会糊。
 * 5) 刷新是差量更新：节点记录按 id 复用，位置保留；只有新增/消失的节点会改数组与缓冲，
 *    场景对象、材质、相机都不重建。
 */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

// 后处理（泛光）链是“可选能力”：这批 addons 内部会 import ./Pass.js，
// 仓库 vendor 里如果少这个文件，静态 import 会让整个模块图 404、大屏直接白屏。
// 所以这四个模块用动态 import + try/catch：能加载就上 UnrealBloomPass 泛光，
// 加载不到就降级成直接渲染（同时把材质的边缘发光调高，视觉不至于塌）。

/* ==========================================================================
 * 常量与配色
 * ========================================================================== */

const GRAPH_URL = '/api/wall/graph?events=30';
const REFRESH_MS = 10000;
const AUTH_STORAGE_KEY = 'cyberstrike-auth';

const DPR_CAP = 2;

// 图规模上限（后端主机上限 500 + 情报，超出部分不画，但统计面板仍用后端汇总值）
const MAX_HOSTS = 520;
const MAX_IOCS = 1080;
const MAX_EDGES = 4000;

// 只有这些主机参与力导向，其余静态分布（这是避免 O(n^2) 卡死的关键）
const MAX_ACTIVE_HOSTS = 160;

// 粒子流并发上限
const MAX_FLOW_EDGES = 30;
const FLOW_DOTS = 6;
const RECENT_WINDOW_MS = 60000;

// 空间尺度
const STAGE_RADIUS = 26;
const ACTIVE_RADIUS = 15.5;
const HOST_BASE_RADIUS = 0.62;

const SEVERITY_HEX = {
    critical: 0xff3b5c,
    high: 0xff8a3d,
    medium: 0xffd24a,
    low: 0x4aa8ff,
    info: 0x8a94a6,
};

const SEVERITY_CSS = {
    critical: '#ff3b5c',
    high: '#ff8a3d',
    medium: '#ffd24a',
    low: '#4aa8ff',
    info: '#8a94a6',
};

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// 边的 IOC 状态配色：observed 黄 / confirmed 橙 / blocked 暗灰（静态、不流动的断流）
const EDGE_HEX = {
    observed: 0xffd24a,
    confirmed: 0xff8a3d,
    blocked: 0x39424f,
    false_positive: 0x4aa8ff,
};

/* ==========================================================================
 * 小工具
 * ========================================================================== */

function el(id) {
    return document.getElementById(id);
}

function esc(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function clamp01(value, fallback) {
    const n = Number(value);
    if (!isFinite(n)) return fallback === undefined ? 1 : fallback;
    if (n < 0) return 0;
    if (n > 1) return 1;
    return n;
}

function pad2(n) {
    return n < 10 ? '0' + n : String(n);
}

function fmtInt(value) {
    const n = Number(value);
    if (!isFinite(n)) return '0';
    return n.toLocaleString('zh-CN');
}

function parseTs(value) {
    if (!value) return 0;
    if (typeof value === 'number') return value;
    const s = String(value).trim();
    if (!s) return 0;
    let t = Date.parse(s);
    if (!isNaN(t)) return t;
    // SQLite 常见的 "2026-11-21 10:00:00"（空格分隔、无时区）在 Safari 里 Date.parse 会得到 NaN，
    // 这里手动拆开按本地时间构造，避免时间列全部变成占位符
    const m = s.match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
    if (m) {
        t = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
            Number(m[4]), Number(m[5]), Number(m[6])).getTime();
        if (!isNaN(t)) return t;
    }
    return 0;
}

function fmtClock(value) {
    const t = typeof value === 'number' ? value : parseTs(value);
    if (!t) return '--:--:--';
    const d = new Date(t);
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

function fmtDateTime(value) {
    const t = typeof value === 'number' ? value : parseTs(value);
    if (!t) return '--';
    const d = new Date(t);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate())
        + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

// 稳定哈希：同一 id 每次刷新都得到同一个 [0,1) 值（脉动相位、IO C 偏移方向要用它）
function hash01(str, salt) {
    const s = String(str == null ? '' : str);
    let h = 2166136261 ^ (salt || 0);
    for (let i = 0; i < s.length; i++) {
        h ^= s.charCodeAt(i);
        h = Math.imul(h, 16777619);
    }
    h ^= h >>> 13;
    h = Math.imul(h, 2246822507);
    h ^= h >>> 16;
    return ((h >>> 0) % 1000003) / 1000003;
}

function sevKey(value) {
    const s = String(value == null ? '' : value).trim().toLowerCase();
    if (s === 'critical' || s === 'crit' || s === 'severe') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium' || s === 'moderate' || s === 'mid') return 'medium';
    if (s === 'low') return 'low';
    return 'info';
}

function sevRank(value) {
    return SEVERITY_RANK[sevKey(value)] || 0;
}

// fibonacci 球：把第 i 个点均匀铺在（压扁的）球面上，用来给静态节点一个不规则但稳定的站位
function fibSphere(i, n, radius, out) {
    const total = Math.max(1, n);
    const y = 1 - ((i + 0.5) * 2) / total;
    const r = Math.sqrt(Math.max(0, 1 - y * y));
    const theta = i * 2.399963229728653;
    out.set(Math.cos(theta) * r * radius, y * radius * 0.7, Math.sin(theta) * r * radius);
    return out;
}

function hostRadius(findings) {
    const f = Math.max(0, Number(findings) || 0);
    return Math.min(3.1, HOST_BASE_RADIUS + Math.log2(1 + f) * 0.34);
}

function iocRadius(hits) {
    const h = Math.max(0, Number(hits) || 0);
    return Math.min(0.95, 0.4 + h * 0.05);
}

function hostRisk(node) {
    const raw = Number(node && node.risk_score);
    if (isFinite(raw) && raw > 0) return raw;
    const findings = Number(node && node.findings_open) || 0;
    const hits = Number(node && node.ioc_hits) || 0;
    return sevRank(node && node.severity) * 14
        + Math.min(60, Math.log2(1 + findings) * 12)
        + Math.min(26, hits * 4);
}

/* ==========================================================================
 * 场景对象与状态
 * ========================================================================== */

let renderer = null;
let scene = null;
let camera = null;
let controls = null;
let composer = null;
let bloomPass = null;
let postFxReady = false;

let hostMesh = null;
let iocMesh = null;
let ringMesh = null;
let hostMat = null;
let iocMat = null;
let ringMat = null;

let edgeGeom = null;
let flowGeom = null;
let dust = null;
let gridHelper = null;
let orbitGroupA = null;
let orbitGroupB = null;
let glowMat = null;

const nodes = new Map();   // id -> 节点记录（跨刷新保留，做差量更新）
let hostList = [];         // rec[]，索引 == hostMesh 实例索引
let iocList = [];          // rec[]，索引 == iocMesh 实例索引
let activeHosts = [];      // rec[]，参与力导向的主机
let liveEdges = [];        // { source, target, status, blocked, hits, color }
let flowEdges = [];        // liveEdges 的子集（最多 MAX_FLOW_EDGES 条）
let flowPhase = [];

const edgePositions = new Float32Array(MAX_EDGES * 2 * 3);
const edgeColors = new Float32Array(MAX_EDGES * 2 * 3);
const flowPositions = new Float32Array(MAX_FLOW_EDGES * FLOW_DOTS * 3);
const flowColors = new Float32Array(MAX_FLOW_EDGES * FLOW_DOTS * 3);

const _m = new THREE.Matrix4();
const _p = new THREE.Vector3();
const _s = new THREE.Vector3();
const _proj = new THREE.Vector3();
const IDENTITY_Q = new THREE.Quaternion();
const RING_Q = new THREE.Quaternion().setFromEuler(new THREE.Euler(-Math.PI / 2, 0, 0));

let sceneTime = 0;
let flowTime = 0;
let layoutTime = 0;
let forceBuf = new Float32Array(0);

let rafId = 0;
let running = false;
let lastFrameTs = 0;
let introT = 0;
let userInteracted = false;
let pointerHeld = false;
let resumeTimer = 0;

let hostMatrixDirty = false;
let ringMatrixDirty = false;
let iocMatrixDirty = false;

let pointerX = -1;
let pointerY = -1;
let pointerClientX = 0;
let pointerClientY = 0;
let pointerInside = false;
let hoverRec = null;
let pickFrame = 0;
let downPoint = null;
let tooltipKey = '';
let tickerKey = '';
let refreshing = false;

let hasWebGL = false;
let webglMissing = false;
let flowQuiet = false;

/* ==========================================================================
 * 数据拉取
 * ========================================================================== */

// 大屏是独立页面，没有加载 auth.js（那套依赖主界面 DOM），
// 所以这里自己从 localStorage 取 Bearer Token；取不到就退回同源 Cookie/凭证。
function readToken() {
    try {
        const raw = window.localStorage.getItem(AUTH_STORAGE_KEY);
        if (!raw) return '';
        const stored = JSON.parse(raw);
        return stored && typeof stored.token === 'string' ? stored.token : '';
    } catch (err) {
        return '';
    }
}

async function fetchGraph() {
    const headers = {};
    const token = readToken();
    if (token) headers.Authorization = 'Bearer ' + token;

    const res = await fetch(GRAPH_URL, {
        method: 'GET',
        credentials: 'same-origin',
        headers,
        cache: 'no-store',
    });

    if (!res.ok) {
        let message = 'HTTP ' + res.status;
        try {
            const body = await res.json();
            if (body && body.error) message = String(body.error);
        } catch (err) { /* 响应不是 JSON，就用状态码 */ }
        const fail = new Error(message);
        fail.status = res.status;
        throw fail;
    }
    return res.json();
}

function setStatus(text, tone) {
    const chip = el('wall-status-chip');
    if (!chip) return;
    chip.textContent = text;
    chip.classList.toggle('is-stale', tone === 'stale');
    chip.classList.toggle('is-error', tone === 'error');
}

function showNotice(text) {
    const box = el('wall-notice');
    if (!box) return;
    box.textContent = text;
    box.hidden = false;
}

function hideNotice() {
    const box = el('wall-notice');
    if (box) box.hidden = true;
}

async function refreshGraph() {
    if (refreshing) return;   // 上一次还没回来就不叠请求
    refreshing = true;
    try {
        const graph = await fetchGraph();
        applyGraph(graph);
        setStatus('已连接', 'ok');

        const stats = (graph && graph.stats) || {};
        const volume = (Number(stats.hosts) || 0) + (Number(stats.ioc_total) || 0)
            + (Number(stats.findings_open) || 0);
        if (!volume) {
            showNotice('暂无态势数据：还没有主机或情报进入采集范围，背景沙盘继续待命。');
        } else if (webglMissing) {
            showNotice('当前环境不支持 WebGL，三维沙盘无法渲染；统计与事件仍在持续刷新。');
        } else {
            hideNotice();
        }
    } catch (err) {
        const status = err && err.status;
        if (status === 401) {
            setStatus('未登录', 'error');
            showNotice('未登录或会话已过期：请先在主界面登录，然后刷新本页。');
        } else if (status === 403) {
            setStatus('无权限', 'error');
            showNotice('当前账号没有主机读取权限（host:read），无法展示态势数据。');
        } else {
            setStatus('重连中', 'stale');
            showNotice('态势数据读取失败：' + (err && err.message ? err.message : '未知错误')
                + '。背景动画继续运行，10 秒后自动重试。');
        }
    } finally {
        refreshing = false;
    }
}

/* ==========================================================================
 * 图数据 → 节点记录（差量更新）
 * ========================================================================== */

function byHostRisk(a, b) {
    return hostRisk(b) - hostRisk(a);
}

function byIocWeight(a, b) {
    return (Number(b && b.ioc_hits) || 0) - (Number(a && a.ioc_hits) || 0);
}

function edgeColorRecord(edge) {
    const key = String((edge && edge.status) || 'observed');
    const hex = EDGE_HEX[key] !== undefined ? EDGE_HEX[key] : EDGE_HEX.observed;
    const c = new THREE.Color(hex);
    const hits = Number(edge && edge.hits) || 0;
    // 命中越多越亮；blocked 保持暗灰，视觉上是"已经掐断的线"
    const gain = key === 'blocked' ? 0.55 : 0.5 + Math.min(0.7, hits * 0.06);
    return { r: c.r * gain, g: c.g * gain, b: c.b * gain };
}

function ensureHostRec(data, index, total, active) {
    const id = String(data.id);
    const sev = sevKey(data.severity);
    const findings = Number(data.findings_open) || 0;
    const hits = Number(data.ioc_hits) || 0;
    const risk = hostRisk(data);
    const radius = hostRadius(findings);

    let rec = nodes.get(id);
    if (!rec) {
        rec = {
            id: id,
            kind: 'host',
            data: data,
            pos: new THREE.Vector3(),
            target: new THREE.Vector3(),
            written: new THREE.Vector3(1e9, 0, 0),
            radius: radius,
            color: new THREE.Color(SEVERITY_HEX[sev] || SEVERITY_HEX.info),
            pulse: hits > 0 ? hash01(id, 7) : -1,
            slot: -1,
            active: !!active,
            risk: risk,
            sev: sev,
            name: String(data.name || data.ip || id),
            ip: String(data.ip || ''),
            group: String(data.group || ''),
            findings: findings,
            hits: hits,
            health: clamp01(data.health, 0.85),
            status: String(data.status || ''),
            lastSeen: String(data.last_seen || ''),
        };
        // 首次出现：活跃主机落在核心球内，静态主机落在球壳格点上
        fibSphere(index, total, active ? STAGE_RADIUS * 0.52 : STAGE_RADIUS * 1.04, rec.pos);
        rec.target.copy(rec.pos);
        nodes.set(id, rec);
        return rec;
    }

    // 已存在：只刷新数据与外观，位置保持（这是"差量"的核心）
    rec.data = data;
    rec.risk = risk;
    rec.sev = sev;
    rec.name = String(data.name || data.ip || id);
    rec.ip = String(data.ip || '');
    rec.group = String(data.group || '');
    rec.findings = findings;
    rec.hits = hits;
    rec.health = clamp01(data.health, 0.85);
    rec.status = String(data.status || '');
    rec.lastSeen = String(data.last_seen || '');
    rec.radius = radius;
    rec.color.setHex(SEVERITY_HEX[sev] || SEVERITY_HEX.info);
    if (hits > 0) {
        if (rec.pulse < 0) rec.pulse = hash01(id, 7);
    } else {
        rec.pulse = -1;
    }
    if (rec.active !== !!active) {
        rec.active = !!active;
    }
    if (!rec.active) {
        // 静态机群：固定在球壳格点上，位置稳定、永不参与两两计算
        fibSphere(index, total, STAGE_RADIUS * 1.04, rec.target);
    }
    // 半径/颜色变了也需要重写矩阵
    rec.written.set(1e9, 0, 0);
    return rec;
}

function ensureIocRec(data, index, total) {
    const id = String(data.id);
    const sev = sevKey(data.severity);
    const hits = Number(data.ioc_hits) || 0;
    const status = String(data.status || 'observed');
    const hex = status === 'blocked' ? EDGE_HEX.blocked
        : (status === 'confirmed' ? 0xff8a3d : (status === 'false_positive' ? 0x4aa8ff : 0xffd24a));
    const radius = iocRadius(hits);

    let rec = nodes.get(id);
    if (!rec) {
        rec = {
            id: id,
            kind: 'ioc',
            data: data,
            pos: new THREE.Vector3(),
            target: new THREE.Vector3(),
            written: new THREE.Vector3(1e9, 0, 0),
            homePos: new THREE.Vector3(),
            offset: new THREE.Vector3(),
            radius: radius,
            color: new THREE.Color(hex),
            pulse: hash01(id, 11),
            slot: -1,
            anchors: [],
            active: false,
            risk: hits * 5,
            sev: sev,
            name: String(data.name || data.value || id),
            value: String(data.value || data.name || ''),
            iocType: String(data.ioc_type || data.type || ''),
            status: status,
            hits: hits,
            lastSeen: String(data.last_seen || ''),
        };
        // 无主机的 IOC 站到外层球壳上
        fibSphere(index, total, STAGE_RADIUS * 1.16, rec.homePos);
        fibSphere(index + total, total, STAGE_RADIUS * 1.16, rec.pos);
        // 相对主机的固定偏移方向（哈希决定，刷新不变）
        const a = hash01(id, 3) * Math.PI * 2;
        const b = Math.acos(2 * hash01(id, 5) - 1);
        const dist = 2.4 + hash01(id, 9) * 2.4;
        rec.offset.set(
            Math.sin(b) * Math.cos(a) * dist,
            Math.cos(b) * dist * 0.62,
            Math.sin(b) * Math.sin(a) * dist
        );
        rec.target.copy(rec.pos);
        nodes.set(id, rec);
        return rec;
    }

    rec.data = data;
    rec.sev = sev;
    rec.radius = radius;
    rec.color.setHex(hex);
    rec.name = String(data.name || data.value || id);
    rec.value = String(data.value || data.name || '');
    rec.iocType = String(data.ioc_type || data.type || '');
    rec.status = status;
    rec.hits = hits;
    rec.lastSeen = String(data.last_seen || '');
    rec.written.set(1e9, 0, 0);
    return rec;
}

function applyGraph(graph) {
    if (!graph || typeof graph !== 'object') return;

    const rawNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
    const rawEdges = Array.isArray(graph.edges) ? graph.edges : [];

    const rawHosts = [];
    const rawIocs = [];
    for (let i = 0; i < rawNodes.length; i++) {
        const n = rawNodes[i];
        if (!n || !n.id) continue;
        if (n.kind === 'ioc') rawIocs.push(n);
        else rawHosts.push(n);
    }
    rawHosts.sort(byHostRisk);
    rawIocs.sort(byIocWeight);

    const hostData = rawHosts.slice(0, MAX_HOSTS);
    const iocData = rawIocs.slice(0, MAX_IOCS);

    // 参与力导向的主机：先照顾"被打过的"和"高/严重"，剩余名额按风险补齐
    const activeIds = new Set();
    for (let i = 0; i < hostData.length && activeIds.size < MAX_ACTIVE_HOSTS; i++) {
        const h = hostData[i];
        if ((Number(h.ioc_hits) || 0) > 0 || sevRank(h.severity) >= 3) activeIds.add(String(h.id));
    }
    for (let i = 0; i < hostData.length && activeIds.size < MAX_ACTIVE_HOSTS; i++) {
        activeIds.add(String(hostData[i].id));
    }

    const nextHosts = [];
    for (let i = 0; i < hostData.length; i++) {
        nextHosts.push(ensureHostRec(hostData[i], i, hostData.length, activeIds.has(String(hostData[i].id))));
    }
    const nextIocs = [];
    for (let i = 0; i < iocData.length; i++) {
        nextIocs.push(ensureIocRec(iocData[i], i, iocData.length));
    }

    // slot 重排（instanced 索引跟着列表走）
    for (let i = 0; i < hostList.length; i++) hostList[i].slot = -1;
    for (let i = 0; i < iocList.length; i++) iocList[i].slot = -1;
    hostList = nextHosts;
    iocList = nextIocs;
    for (let i = 0; i < hostList.length; i++) hostList[i].slot = i;
    for (let i = 0; i < iocList.length; i++) iocList[i].slot = i;

    activeHosts = [];
    for (let i = 0; i < hostList.length; i++) {
        if (hostList[i].active) activeHosts.push(hostList[i]);
    }

    // IOC 的锚点：它命中的主机（最多 3 台，避免大量边时每帧遍历过重）
    // 注意要清所有 IOC 记录：本轮被截断、不渲染的那些如果不清，会一直往 anchors 里堆对象
    nodes.forEach(function (rec) {
        if (rec.kind === 'ioc') rec.anchors.length = 0;
    });

    // 关系线
    const nextEdges = [];
    for (let i = 0; i < rawEdges.length; i++) {
        const e = rawEdges[i];
        if (!e || !e.source || !e.target) continue;
        const src = nodes.get(String(e.source));
        const dst = nodes.get(String(e.target));
        if (!src || !dst || src.kind !== 'ioc' || dst.kind !== 'host') continue;  // RBAC 过滤掉的主机在这里自然消失
        const record = {
            id: String(e.id || String(e.source) + '>' + String(e.target)),
            source: src,
            target: dst,
            status: String(e.status || 'observed'),
            blocked: String(e.status) === 'blocked',
            severity: sevKey(e.severity),
            iocType: String(e.ioc_type || ''),
            hits: Number(e.hits) || 0,
            ts: parseTs(e.last_seen),
            color: edgeColorRecord(e),
        };
        nextEdges.push(record);
        if (src.anchors.length < 3 && dst.slot >= 0) src.anchors.push(dst);
    }
    nextEdges.sort(function (a, b) { return b.hits - a.hits; });
    liveEdges = nextEdges.slice(0, MAX_EDGES);

    // 清理已经不在图里的节点记录（否则 Map 会一直长）
    const keep = new Set();
    for (let i = 0; i < hostList.length; i++) keep.add(hostList[i].id);
    for (let i = 0; i < iocList.length; i++) keep.add(iocList[i].id);
    const drop = [];
    nodes.forEach(function (rec, id) {
        if (!keep.has(id)) drop.push(id);
    });
    for (let i = 0; i < drop.length; i++) nodes.delete(drop[i]);

    pickFlowEdges();
    syncInstanceAttributes();
    writeEdgeColors();

    renderStats(graph.stats || {});
    renderRiskList();
    renderTicker(graph.events || []);
    renderGeneratedAt(graph.generated_at);
}

/* ==========================================================================
 * InstancedMesh 属性写入（只在数据变化时批量写一次）
 * ========================================================================== */

function instAttr(mesh, name) {
    return mesh ? mesh.geometry.getAttribute(name) : null;
}

function syncInstanceAttributes() {
    if (hostMesh) {
        const colors = instAttr(hostMesh, 'aColor');
        const pulse = instAttr(hostMesh, 'aPulse');
        const ringColors = instAttr(ringMesh, 'aColor');
        const ringFill = instAttr(ringMesh, 'aFill');
        for (let i = 0; i < hostList.length; i++) {
            const rec = hostList[i];
            if (colors) colors.setXYZ(i, rec.color.r, rec.color.g, rec.color.b);
            if (pulse) pulse.setX(i, rec.pulse);
            if (ringColors) ringColors.setXYZ(i, rec.color.r, rec.color.g, rec.color.b);
            if (ringFill) ringFill.setX(i, rec.health);
        }
        if (colors) colors.needsUpdate = true;
        if (pulse) pulse.needsUpdate = true;
        if (ringColors) ringColors.needsUpdate = true;
        if (ringFill) ringFill.needsUpdate = true;
        hostMesh.count = hostList.length;
        if (ringMesh) ringMesh.count = hostList.length;
        hostMatrixDirty = true;
        ringMatrixDirty = true;
    }

    if (iocMesh) {
        const colors = instAttr(iocMesh, 'aColor');
        const pulse = instAttr(iocMesh, 'aPulse');
        for (let i = 0; i < iocList.length; i++) {
            const rec = iocList[i];
            if (colors) colors.setXYZ(i, rec.color.r, rec.color.g, rec.color.b);
            if (pulse) pulse.setX(i, rec.pulse);
        }
        if (colors) colors.needsUpdate = true;
        if (pulse) pulse.needsUpdate = true;
        iocMesh.count = iocList.length;
        iocMatrixDirty = true;
    }
}

function writeEdgeColors() {
    if (!edgeGeom) return;
    const attr = edgeGeom.getAttribute('color');
    if (!attr) return;
    const n = Math.min(liveEdges.length, MAX_EDGES);
    for (let i = 0; i < n; i++) {
        const c = liveEdges[i].color;
        const o = i * 6;
        edgeColors[o] = c.r;
        edgeColors[o + 1] = c.g;
        edgeColors[o + 2] = c.b;
        edgeColors[o + 3] = c.r * 0.72;
        edgeColors[o + 4] = c.g * 0.72;
        edgeColors[o + 5] = c.b * 0.72;
    }
    markDynamic(attr, n * 6);
    edgeGeom.setDrawRange(0, n * 2);
}

/* ==========================================================================
 * 覆盖层（HTML，不放 3D 里）
 * ========================================================================== */

const STAT_ITEMS = [
    { key: 'hosts', label: '主机总数', tone: '' },
    { key: 'hosts_reachable', label: '在线主机', tone: 'low' },
    { key: 'findings_open', label: '开放发现', tone: '' },
    { key: 'findings_high', label: '高危发现', tone: 'high' },
    { key: 'kev_hits', label: 'KEV 命中', tone: 'critical' },
    { key: 'ioc_total', label: '情报总量', tone: '' },
    { key: 'ioc_observed', label: '情报观察', tone: 'medium' },
    { key: 'ioc_confirmed', label: '情报确认', tone: 'high' },
    { key: 'ioc_blocked', label: '已封禁', tone: '' },
];

const statPrev = {};

function renderStats(stats) {
    const grid = el('wall-stat-grid');
    if (!grid) return;
    const s = stats || {};
    const html = [];
    for (let i = 0; i < STAT_ITEMS.length; i++) {
        const item = STAT_ITEMS[i];
        const value = Number(s[item.key]) || 0;
        const changed = statPrev[item.key] !== undefined && statPrev[item.key] !== value;
        statPrev[item.key] = value;
        html.push(
            '<div class="wall-stat' + (item.tone ? ' wall-stat--' + item.tone : '') + '">'
            + '<span class="wall-stat__label">' + esc(item.label) + '</span>'
            + '<span class="wall-stat__value' + (changed ? ' is-bump' : '') + '">' + esc(fmtInt(value)) + '</span>'
            + '</div>'
        );
    }
    grid.innerHTML = html.join('');
}

function renderRiskList() {
    const list = el('wall-risk-list');
    if (!list) return;

    const sorted = hostList.slice().sort(function (a, b) { return b.risk - a.risk; });
    const top = sorted.slice(0, 8);
    if (!top.length) {
        list.innerHTML = '<li class="wall-risk-empty">暂无风险主机</li>';
        return;
    }

    const html = [];
    for (let i = 0; i < top.length; i++) {
        const rec = top[i];
        const color = SEVERITY_CSS[rec.sev] || SEVERITY_CSS.info;
        const fill = Math.max(4, Math.min(100, Math.round(rec.risk)));
        const score = Math.round(Math.min(999, rec.risk));
        html.push(
            '<li class="wall-risk-item" style="--risk-color:' + color + ';--risk-fill:' + fill + '%;animation-delay:'
            + (i * 45) + 'ms">'
            + '<span class="wall-risk-item__name" title="' + esc(rec.name) + '">' + esc(rec.name) + '</span>'
            + '<span class="wall-risk-item__score">' + esc(String(score)) + '</span>'
            + '<span class="wall-risk-item__ip">' + esc(rec.ip || '—') + '</span>'
            + '<span class="wall-risk-item__meta">'
            + '<span class="wall-risk-bar"><i></i></span>'
            + '<span>发现 ' + esc(String(rec.findings)) + '</span>'
            + '<span>命中 ' + esc(String(rec.hits)) + '</span>'
            + '</span>'
            + '</li>'
        );
    }
    list.innerHTML = html.join('');
}

function renderTicker(events) {
    const track = el('wall-ticker-track');
    if (!track) return;

    const items = (Array.isArray(events) ? events : []).slice(0, 30);

    // 内容没变就不重建，否则跑马灯每 10 秒会跳回起点
    let signature = String(items.length);
    for (let i = 0; i < items.length; i++) {
        const ev = items[i] || {};
        signature += '|' + (ev.ts || '') + '~' + (ev.title || '') + '~' + (ev.severity || '');
    }
    if (signature === tickerKey) return;
    tickerKey = signature;

    if (!items.length) {
        track.style.animation = 'none';
        track.innerHTML = '<div class="wall-ticker__empty">暂无事件记录</div>';
        return;
    }

    const one = [];
    for (let i = 0; i < items.length; i++) {
        const ev = items[i] || {};
        const color = SEVERITY_CSS[sevKey(ev.severity)] || SEVERITY_CSS.info;
        one.push(
            '<span class="wall-ticker__item" style="--sev-color:' + color + '">'
            + '<i class="wall-ticker__sev"></i>'
            + '<span class="wall-ticker__time">' + esc(fmtClock(ev.ts)) + '</span>'
            + (ev.host ? '<span class="wall-ticker__host">' + esc(ev.host) + '</span>' : '')
            + '<span>' + esc(ev.title || ev.kind || '事件') + '</span>'
            + '</span>'
        );
    }
    // 两份相同内容 + translateX(-50%) 的动画，滚动无缝
    const group = '<div class="wall-ticker__group">' + one.join('') + '</div>';
    track.style.animation = '';
    track.innerHTML = group + group;
}

function renderGeneratedAt(value) {
    const box = el('wall-generated');
    if (!box) return;
    box.textContent = value ? '数据时间 ' + fmtDateTime(value) : '数据时间 --';
}

/* ==========================================================================
 * tooltip
 * ========================================================================== */

function tooltipRow(label, value) {
    return '<div class="wall-tooltip__row"><span>' + esc(label) + '</span><b>' + esc(value) + '</b></div>';
}

function tooltipHtml(rec) {
    const color = SEVERITY_CSS[rec.sev] || SEVERITY_CSS.info;
    if (rec.kind === 'host') {
        return '<div class="wall-tooltip__title"><i class="wall-legend__dot" style="--dot:' + color + '"></i>'
            + esc(rec.name) + '</div>'
            + tooltipRow('地址', rec.ip || '—')
            + tooltipRow('分组', rec.group || '—')
            + tooltipRow('状态', rec.status || '—')
            + tooltipRow('风险分', String(Math.round(Math.min(999, rec.risk))))
            + tooltipRow('开放发现', String(rec.findings))
            + tooltipRow('情报命中', String(rec.hits))
            + '<div class="wall-tooltip__hint">点击 → 打开主机管理</div>';
    }
    return '<div class="wall-tooltip__title"><i class="wall-legend__dot" style="--dot:' + color + '"></i>'
        + esc(rec.value || rec.name) + '</div>'
        + tooltipRow('类型', rec.iocType || '—')
        + tooltipRow('情报状态', rec.status || '—')
        + tooltipRow('命中主机', String(rec.anchors ? rec.anchors.length : 0) + ' 台')
        + tooltipRow('命中次数', String(rec.hits))
        + tooltipRow('最近出现', rec.lastSeen ? fmtDateTime(rec.lastSeen) : '—');
}

function tooltipSignature(rec) {
    if (!rec) return '';
    return rec.id + '|' + rec.kind + '|' + rec.hits + '|' + rec.findings + '|'
        + rec.status + '|' + Math.round(rec.risk);
}

// 内容只在签名变化时重建，位置每次拾取都更新（跟随鼠标），避免每帧重排 DOM
function showTooltip(rec, clientX, clientY) {
    const tip = el('wall-tooltip');
    if (!tip) return;

    if (!rec) {
        if (!tip.hidden) tip.hidden = true;
        tooltipKey = '';
        return;
    }

    const key = tooltipSignature(rec);
    if (key !== tooltipKey) {
        tip.innerHTML = tooltipHtml(rec);
        tooltipKey = key;
    }
    if (tip.hidden) tip.hidden = false;

    // 用 offsetWidth/Height 做翻转，保证贴边时不溢出视口
    const w = tip.offsetWidth || 220;
    const h = tip.offsetHeight || 140;
    let left = clientX + 16;
    let top = clientY + 16;
    if (left + w > window.innerWidth - 12) left = clientX - w - 16;
    if (top + h > window.innerHeight - 12) top = clientY - h - 16;
    tip.style.left = Math.max(8, left) + 'px';
    tip.style.top = Math.max(8, top) + 'px';
}

/* ==========================================================================
 * three.js 场景
 * ========================================================================== */

const NODE_VERT = `
attribute vec3 aColor;
attribute float aPulse;

uniform float uTime;
uniform float uPulseAmp;

varying vec3 vColor;
varying vec3 vNormalV;
varying vec3 vViewDir;
varying float vPulse;

void main() {
    vec3 p = position;
    float pulse = 0.0;
    if (aPulse >= 0.0) {
        pulse = 0.5 + 0.5 * sin(uTime * 2.4 + aPulse * 6.28318);
        p *= 1.0 + uPulseAmp * pulse;
    }
    vec4 mv = modelViewMatrix * instanceMatrix * vec4(p, 1.0);
    vViewDir = normalize(-mv.xyz);
    vNormalV = normalize(normalMatrix * normal);
    vColor = aColor;
    vPulse = pulse;
    gl_Position = projectionMatrix * mv;
}
`;

const NODE_FRAG = `
uniform float uOpacity;
uniform float uRimPower;
uniform float uGlow;

varying vec3 vColor;
varying vec3 vNormalV;
varying vec3 vViewDir;
varying float vPulse;

void main() {
    vec3 n = normalize(vNormalV);
    vec3 v = normalize(vViewDir);
    float ndv = clamp(dot(n, v), 0.0, 1.0);
    // 菲涅尔：中心暗、边缘亮，全息球体的核心手感
    float rim = pow(1.0 - ndv, uRimPower);
    vec3 col = vColor * (0.10 + 0.18 * ndv + rim * 1.85 * uGlow);
    col += vColor * vPulse * 0.6;
    col += vec3(0.015, 0.045, 0.075) * uGlow;
    float alpha = clamp(0.10 + rim * 1.15 * uGlow + vPulse * 0.35, 0.0, 1.0) * uOpacity;
    gl_FragColor = vec4(col, alpha);
}
`;

const RING_VERT = `
attribute vec3 aColor;
attribute float aFill;

varying vec2 vQuad;
varying vec3 vColor;
varying float vFill;

void main() {
    vQuad = position.xy * 2.0;
    vColor = aColor;
    vFill = aFill;
    gl_Position = projectionMatrix * modelViewMatrix * instanceMatrix * vec4(position, 1.0);
}
`;

const RING_FRAG = `
uniform float uTime;
uniform float uGlow;

varying vec2 vQuad;
varying vec3 vColor;
varying float vFill;

void main() {
    float r = length(vQuad);
    float outer = 0.94;
    // health 越差，环带越宽（一眼看出"这台机器在漏"）
    float width = mix(0.34, 0.06, clamp(vFill, 0.0, 1.0));
    float inner = outer - width;
    float ring = smoothstep(inner, inner + 0.035, r) * (1.0 - smoothstep(outer - 0.02, outer + 0.012, r));
    if (ring <= 0.002) discard;
    float ang = atan(vQuad.y, vQuad.x);
    float sweep = 0.32 + 0.68 * pow(0.5 + 0.5 * sin(ang * 3.0 - uTime * 1.7), 2.0);
    vec3 col = vColor * (0.5 + 1.5 * sweep) * uGlow;
    gl_FragColor = vec4(col, ring * (0.25 + 0.75 * sweep) * 0.85);
}
`;

function makeInstanced(geometry, material, capacity, attrs) {
    const mesh = new THREE.InstancedMesh(geometry, material, capacity);
    mesh.count = 0;
    mesh.frustumCulled = false;
    mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    for (let i = 0; i < attrs.length; i++) {
        const name = attrs[i][0];
        const size = attrs[i][1];
        geometry.setAttribute(name, new THREE.InstancedBufferAttribute(new Float32Array(capacity * size), size));
    }
    return mesh;
}

function buildDust() {
    const count = 1600;
    const positions = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
        const r = 34 + Math.random() * 76;
        const theta = Math.random() * Math.PI * 2;
        const phi = Math.acos(2 * Math.random() - 1);
        positions[i * 3] = Math.sin(phi) * Math.cos(theta) * r;
        positions[i * 3 + 1] = Math.cos(phi) * r * 0.6;
        positions[i * 3 + 2] = Math.sin(phi) * Math.sin(theta) * r;
    }
    const geom = new THREE.BufferGeometry();
    geom.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const mat = new THREE.PointsMaterial({
        color: 0x6fd8ff,
        size: 0.42,
        sizeAttenuation: true,
        transparent: true,
        opacity: 0.55,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
    });
    dust = new THREE.Points(geom, mat);
    scene.add(dust);
}

function buildGrid() {
    gridHelper = new THREE.PolarGridHelper(STAGE_RADIUS * 1.6, 16, 9, 96, 0x114d68, 0x0b3048);
    gridHelper.position.y = -16;
    if (gridHelper.material) {
        gridHelper.material.transparent = true;
        gridHelper.material.opacity = 0.6;
        gridHelper.material.blending = THREE.AdditiveBlending;
        gridHelper.material.depthWrite = false;
    }
    scene.add(gridHelper);

    // 地平线光晕：让网格中央有一层柔和的"投影台"光
    glowMat = new THREE.ShaderMaterial({
        uniforms: {
            uColor: { value: new THREE.Color(0x2a86c8) },
            uStrength: { value: 0.5 },
        },
        vertexShader: `
            varying vec2 vUv;
            void main() {
                vUv = uv;
                gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
            }
        `,
        fragmentShader: `
            varying vec2 vUv;
            uniform vec3 uColor;
            uniform float uStrength;
            void main() {
                float d = clamp(length(vUv - 0.5) * 2.0, 0.0, 1.0);
                float a = pow(1.0 - d, 3.2) * uStrength;
                gl_FragColor = vec4(uColor, a);
            }
        `,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        depthTest: true,
    });
    const glow = new THREE.Mesh(new THREE.CircleGeometry(STAGE_RADIUS * 1.7, 80), glowMat);
    glow.rotation.x = -Math.PI / 2;
    glow.position.y = -16.02;
    scene.add(glow);
}

function buildOrbits() {
    // 两段缓慢旋转的弧：纯装饰，提供"扫描轨道"的科技感
    function arc(radius, thickness, arcLen, color, opacity) {
        const geom = new THREE.TorusGeometry(radius, thickness, 6, 140, arcLen);
        const mat = new THREE.MeshBasicMaterial({
            color: color,
            transparent: true,
            opacity: opacity,
            blending: THREE.AdditiveBlending,
            depthWrite: false,
        });
        return new THREE.Mesh(geom, mat);
    }

    orbitGroupA = new THREE.Group();
    const a1 = arc(STAGE_RADIUS * 1.18, 0.07, Math.PI * 0.4, 0x3fa8d8, 0.5);
    a1.rotation.set(Math.PI * 0.5, 0, Math.PI * 0.15);
    orbitGroupA.add(a1);
    scene.add(orbitGroupA);

    orbitGroupB = new THREE.Group();
    const b1 = arc(STAGE_RADIUS * 1.32, 0.05, Math.PI * 0.28, 0x2d7fa8, 0.42);
    b1.rotation.set(Math.PI * 0.42, Math.PI * 0.25, 0);
    orbitGroupB.add(b1);
    scene.add(orbitGroupB);
}

function buildNodes() {
    hostMat = new THREE.ShaderMaterial({
        uniforms: {
            uTime: { value: 0 },
            uOpacity: { value: 1 },
            uRimPower: { value: 2.3 },
            uPulseAmp: { value: 0.15 },
            uGlow: { value: 1 },
        },
        vertexShader: NODE_VERT,
        fragmentShader: NODE_FRAG,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
    });
    hostMesh = makeInstanced(new THREE.SphereGeometry(1, 18, 12), hostMat, MAX_HOSTS, [['aColor', 3], ['aPulse', 1]]);
    scene.add(hostMesh);

    iocMat = new THREE.ShaderMaterial({
        uniforms: {
            uTime: { value: 0 },
            uOpacity: { value: 1 },
            uRimPower: { value: 1.7 },
            uPulseAmp: { value: 0.3 },
            uGlow: { value: 1 },
        },
        vertexShader: NODE_VERT,
        fragmentShader: NODE_FRAG,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
    });
    iocMesh = makeInstanced(new THREE.IcosahedronGeometry(1, 0), iocMat, MAX_IOCS, [['aColor', 3], ['aPulse', 1]]);
    scene.add(iocMesh);

    ringMat = new THREE.ShaderMaterial({
        uniforms: { uTime: { value: 0 }, uGlow: { value: 1 } },
        vertexShader: RING_VERT,
        fragmentShader: RING_FRAG,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
    });
    ringMesh = makeInstanced(new THREE.PlaneGeometry(1, 1), ringMat, MAX_HOSTS, [['aColor', 3], ['aFill', 1]]);
    scene.add(ringMesh);
}

function buildEdges() {
    edgeGeom = new THREE.BufferGeometry();
    const posAttr = new THREE.BufferAttribute(edgePositions, 3);
    posAttr.setUsage(THREE.DynamicDrawUsage);
    const colAttr = new THREE.BufferAttribute(edgeColors, 3);
    colAttr.setUsage(THREE.DynamicDrawUsage);
    edgeGeom.setAttribute('position', posAttr);
    edgeGeom.setAttribute('color', colAttr);
    edgeGeom.setDrawRange(0, 0);

    const mat = new THREE.LineBasicMaterial({
        vertexColors: true,
        transparent: true,
        opacity: 0.5,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
    });
    const lines = new THREE.LineSegments(edgeGeom, mat);
    lines.frustumCulled = false;
    scene.add(lines);
}

function buildFlows() {
    flowGeom = new THREE.BufferGeometry();
    const posAttr = new THREE.BufferAttribute(flowPositions, 3);
    posAttr.setUsage(THREE.DynamicDrawUsage);
    const colAttr = new THREE.BufferAttribute(flowColors, 3);
    colAttr.setUsage(THREE.DynamicDrawUsage);
    flowGeom.setAttribute('position', posAttr);
    flowGeom.setAttribute('color', colAttr);
    flowGeom.setDrawRange(0, 0);

    const mat = new THREE.PointsMaterial({
        size: 0.46,
        sizeAttenuation: true,
        vertexColors: true,
        transparent: true,
        opacity: 0.95,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
    });
    const points = new THREE.Points(flowGeom, mat);
    points.frustumCulled = false;
    scene.add(points);
}

function initScene() {
    const stage = el('wall-stage');
    if (!stage) return false;

    // WebGL 探测：不支持时不要白屏，覆盖层照常显示文字提示
    try {
        const probe = document.createElement('canvas');
        const ctx = probe.getContext('webgl2') || probe.getContext('webgl') || probe.getContext('experimental-webgl');
        if (!ctx) return false;
    } catch (err) {
        return false;
    }

    try {
        renderer = new THREE.WebGLRenderer({
            antialias: true,
            alpha: false,
            powerPreference: 'high-performance',
        });
    } catch (err) {
        return false;
    }

    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, DPR_CAP));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x03060d, 1);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    // 不做 tone mapping：严重度色值要和大屏 CSS 完全一致
    renderer.toneMapping = THREE.NoToneMapping;
    stage.appendChild(renderer.domElement);

    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(46, window.innerWidth / window.innerHeight, 0.5, 500);
    camera.position.set(0, 46, 128);

    controls = new OrbitControls(camera, renderer.domElement);
    controls.target.set(0, 0, 0);
    controls.enableDamping = true;
    controls.dampingFactor = 0.055;
    controls.rotateSpeed = 0.55;
    controls.zoomSpeed = 0.7;
    controls.enablePan = false;
    controls.minDistance = 26;
    controls.maxDistance = 160;
    controls.minPolarAngle = Math.PI * 0.08;
    controls.maxPolarAngle = Math.PI * 0.9;
    controls.autoRotate = false;   // 入场动画结束后由主循环接管

    composer = null;
    bloomPass = null;

    buildDust();
    buildGrid();
    buildOrbits();
    buildNodes();
    buildEdges();
    buildFlows();

    hasWebGL = true;
    return true;
}

// 材质边缘发光系数：有泛光时为 1，降级时提高，让没有 bloom 的画面也有辉光感
function applyGlowBoost(amount) {
    if (hostMat) hostMat.uniforms.uGlow.value = amount;
    if (iocMat) iocMat.uniforms.uGlow.value = amount + 0.15;
    if (ringMat) ringMat.uniforms.uGlow.value = amount;
}

// 动态加载后处理链；失败不抛到外面，只降级
async function setupPostFx() {
    try {
        const [composerMod, renderPassMod, bloomMod, outputMod] = await Promise.all([
            import('three/addons/postprocessing/EffectComposer.js'),
            import('three/addons/postprocessing/RenderPass.js'),
            import('three/addons/postprocessing/UnrealBloomPass.js'),
            import('three/addons/postprocessing/OutputPass.js'),
        ]);

        composer = new composerMod.EffectComposer(renderer);
        composer.setPixelRatio(Math.min(window.devicePixelRatio || 1, DPR_CAP));
        composer.setSize(window.innerWidth, window.innerHeight);
        composer.addPass(new renderPassMod.RenderPass(scene, camera));
        bloomPass = new bloomMod.UnrealBloomPass(
            new THREE.Vector2(window.innerWidth, window.innerHeight), 0.92, 0.62, 0.55
        );
        composer.addPass(bloomPass);
        composer.addPass(new outputMod.OutputPass());

        postFxReady = true;
        applyGlowBoost(1);
    } catch (err) {
        postFxReady = false;
        composer = null;
        bloomPass = null;
        console.warn('[wall] 泛光后处理不可用，已降级为直接渲染（vendor 里往往缺 addons/postprocessing/Pass.js）:', err);
        applyGlowBoost(1.6);
    }
}

/* ==========================================================================
 * 实例矩阵与每帧同步
 * ========================================================================== */

function writeHostSlot(index, rec) {
    _s.setScalar(rec.radius);
    _m.compose(rec.pos, IDENTITY_Q, _s);
    hostMesh.setMatrixAt(index, _m);

    // 光环平躺在球体下沿，直径随球体走
    if (ringMesh) {
        _p.set(rec.pos.x, rec.pos.y - rec.radius * 1.02, rec.pos.z);
        _s.setScalar(rec.radius * 4.4);
        _m.compose(_p, RING_Q, _s);
        ringMesh.setMatrixAt(index, _m);
        ringMatrixDirty = true;
    }

    rec.written.copy(rec.pos);
    hostMatrixDirty = true;
}

function writeIocSlot(index, rec) {
    _s.setScalar(rec.radius);
    _m.compose(rec.pos, IDENTITY_Q, _s);
    iocMesh.setMatrixAt(index, _m);
    rec.written.copy(rec.pos);
    iocMatrixDirty = true;
}

function syncInstances(dt) {
    if (!hostMesh) return;
    const k = Math.min(1, dt * 5.5);

    for (let i = 0; i < hostList.length; i++) {
        const rec = hostList[i];
        rec.pos.lerp(rec.target, k);
        if (rec.pos.distanceToSquared(rec.written) > 1e-6) writeHostSlot(i, rec);
    }
    if (hostMatrixDirty) {
        hostMesh.instanceMatrix.needsUpdate = true;
        hostMatrixDirty = false;
    }
    if (ringMatrixDirty && ringMesh) {
        ringMesh.instanceMatrix.needsUpdate = true;
        ringMatrixDirty = false;
    }

    if (!iocMesh) return;
    for (let i = 0; i < iocList.length; i++) {
        const rec = iocList[i];
        rec.pos.lerp(rec.target, Math.min(1, dt * 4.2));
        if (rec.pos.distanceToSquared(rec.written) > 1e-6) writeIocSlot(i, rec);
    }
    if (iocMatrixDirty) {
        iocMesh.instanceMatrix.needsUpdate = true;
        iocMatrixDirty = false;
    }
}

/* ==========================================================================
 * 力导向（只对活跃主机，O(n^2) 且 n <= MAX_ACTIVE_HOSTS）
 * ========================================================================== */

function stepLayout(dt) {
    const n = activeHosts.length;
    if (!n) return;

    layoutTime += dt;
    // 30Hz 足够了，省一半算力
    if (layoutTime < 1 / 30) return;
    const step = Math.min(layoutTime, 0.05);
    layoutTime = 0;

    if (forceBuf.length !== n * 3) forceBuf = new Float32Array(n * 3);
    forceBuf.fill(0);

    const repulsion = 46;
    const cohesion = 0.9;
    const minDist = 3.2;

    for (let i = 0; i < n; i++) {
        const a = activeHosts[i];
        const ap = a.target;
        for (let j = i + 1; j < n; j++) {
            const b = activeHosts[j];
            const bp = b.target;
            let dx = ap.x - bp.x;
            let dy = ap.y - bp.y;
            let dz = ap.z - bp.z;
            let d2 = dx * dx + dy * dy + dz * dz;
            if (d2 < 1e-6) {
                dx = 0.01 + i * 1e-4;
                dy = 0.01;
                dz = 0.01;
                d2 = dx * dx + dy * dy + dz * dz;
            }
            const d = Math.sqrt(d2);
            const sameGroup = a.group !== '' && a.group === b.group;
            let f;
            if (sameGroup) {
                // 同组（同一业务分区）微微抱团，沙盘上就形成"阵地"
                f = -cohesion;
            } else {
                f = repulsion / d2;
            }
            if (d < minDist) f += (minDist - d) * 2.4;
            if (f > 8) f = 8;
            if (f < -1.5) f = -1.5;

            const k = f / d;
            const fx = dx * k;
            const fy = dy * k;
            const fz = dz * k;
            forceBuf[i * 3] += fx;
            forceBuf[i * 3 + 1] += fy;
            forceBuf[i * 3 + 2] += fz;
            forceBuf[j * 3] -= fx;
            forceBuf[j * 3 + 1] -= fy;
            forceBuf[j * 3 + 2] -= fz;
        }
    }

    for (let i = 0; i < n; i++) {
        const rec = activeHosts[i];
        const p = rec.target;
        const fx = forceBuf[i * 3];
        const fy = forceBuf[i * 3 + 1];
        const fz = forceBuf[i * 3 + 2];
        const len = Math.sqrt(fx * fx + fy * fy + fz * fz);
        if (len > 1e-6) {
            // 每帧位移限幅：力大时按上限走，避免数值爆炸
            const stepLen = Math.min(0.45, len * 0.12) * (step / 0.0333);
            const k = stepLen / len;
            p.x += fx * k;
            p.y += fy * k;
            p.z += fz * k;
        }

        // 向心力 + 压扁 + 球壳约束，让云团一直待在镜头里
        p.x *= 0.994;
        p.y *= 0.996;
        p.z *= 0.994;
        const dist = Math.sqrt(p.x * p.x + p.y * p.y + p.z * p.z);
        if (dist > ACTIVE_RADIUS) {
            const s = ACTIVE_RADIUS / dist;
            p.x *= s;
            p.y *= s;
            p.z *= s;
        }
        // 极小的随机扰动，防止对称布局卡死在一条线上
        p.x += (Math.random() - 0.5) * 0.03;
        p.y += (Math.random() - 0.5) * 0.03;
        p.z += (Math.random() - 0.5) * 0.03;
    }
}

function updateIocTargets() {
    for (let i = 0; i < iocList.length; i++) {
        const rec = iocList[i];
        const anchors = rec.anchors;
        if (!anchors || !anchors.length) {
            rec.target.copy(rec.homePos);
            continue;
        }
        let x = 0;
        let y = 0;
        let z = 0;
        for (let j = 0; j < anchors.length; j++) {
            x += anchors[j].pos.x;
            y += anchors[j].pos.y;
            z += anchors[j].pos.z;
        }
        const inv = 1 / anchors.length;
        rec.target.set(
            x * inv + rec.offset.x,
            y * inv + rec.offset.y,
            z * inv + rec.offset.z
        );
    }
}

/* ==========================================================================
 * 关系线与粒子流
 * ========================================================================== */

function updateEdgeLines() {
    if (!edgeGeom) return;
    const n = Math.min(liveEdges.length, MAX_EDGES);
    for (let i = 0; i < n; i++) {
        const edge = liveEdges[i];
        const a = edge.source.pos;
        const b = edge.target.pos;
        const o = i * 6;
        edgePositions[o] = a.x;
        edgePositions[o + 1] = a.y;
        edgePositions[o + 2] = a.z;
        edgePositions[o + 3] = b.x;
        edgePositions[o + 4] = b.y;
        edgePositions[o + 5] = b.z;
    }
    markDynamic(edgeGeom.getAttribute('position'), n * 6);
    edgeGeom.setDrawRange(0, n * 2);
}

function pickFlowEdges() {
    const now = Date.now();
    const recentOpen = [];
    const recentBlocked = [];
    for (let i = 0; i < liveEdges.length; i++) {
        const e = liveEdges[i];
        if (now - e.ts > RECENT_WINDOW_MS) continue;
        if (e.blocked) recentBlocked.push(e);
        else recentOpen.push(e);
    }

    let list = [];
    for (let i = 0; i < recentOpen.length && list.length < MAX_FLOW_EDGES; i++) list.push(recentOpen[i]);
    for (let i = 0; i < recentBlocked.length && list.length < MAX_FLOW_EDGES; i++) list.push(recentBlocked[i]);

    if (!list.length) {
        // 没有任何 60 秒内的命中时，退化成"命中次数最高的少数几条"，
        // 否则大屏会完全静止；此时速度更慢、更暗。
        const fallback = liveEdges.slice().sort(function (a, b) { return b.hits - a.hits; }).slice(0, 10);
        list = fallback;
        flowQuiet = true;
    } else {
        flowQuiet = false;
    }

    flowEdges = list;
    flowPhase = [];
    for (let i = 0; i < list.length; i++) flowPhase.push(hash01(list[i].id, 3 + i));
}

// 只上传真正用到的那段缓冲区间（three 新旧 API 都兼容）
function markDynamic(attr, count) {
    // count<=0 时既不用画也不用传（drawRange 已经置 0）
    if (!attr || count <= 0) return;
    if (typeof attr.clearUpdateRanges === 'function' && typeof attr.addUpdateRange === 'function') {
        attr.clearUpdateRanges();
        attr.addUpdateRange(0, count);
    } else if (attr.updateRange) {
        attr.updateRange.offset = 0;
        attr.updateRange.count = count;
    }
    attr.needsUpdate = true;
}

function updateFlows(dt) {
    if (!flowGeom) return;
    flowTime += dt;

    let count = 0;
    for (let i = 0; i < flowEdges.length; i++) {
        const edge = flowEdges[i];
        const a = edge.source.pos;
        const b = edge.target.pos;
        const speed = (flowQuiet ? 0.14 : 0.3) + Math.min(0.3, edge.hits * 0.02);
        for (let d = 0; d < FLOW_DOTS; d++) {
            const t = (flowTime * speed + flowPhase[i] + d / FLOW_DOTS) % 1;
            let vis;
            if (edge.blocked) {
                // 被掐断：走到中途逆灭，视觉上"流不过来"
                vis = t >= 0.52 ? 0 : Math.min(1, (0.52 - t) / 0.14);
            } else {
                vis = Math.min(1, Math.min(t, 1 - t) * 4.5 + 0.12);
            }
            if (flowQuiet) vis *= 0.5;

            const o = count * 3;
            flowPositions[o] = a.x + (b.x - a.x) * t;
            flowPositions[o + 1] = a.y + (b.y - a.y) * t;
            flowPositions[o + 2] = a.z + (b.z - a.z) * t;
            flowColors[o] = edge.color.r * vis * 1.7;
            flowColors[o + 1] = edge.color.g * vis * 1.7;
            flowColors[o + 2] = edge.color.b * vis * 1.7;
            count++;
            if (count >= MAX_FLOW_EDGES * FLOW_DOTS) break;
        }
        if (count >= MAX_FLOW_EDGES * FLOW_DOTS) break;
    }

    markDynamic(flowGeom.getAttribute('position'), count * 3);
    markDynamic(flowGeom.getAttribute('color'), count * 3);
    flowGeom.setDrawRange(0, count);
}

/* ==========================================================================
 * 相机 / 交互
 * ========================================================================== */

function updateCameraIntro(dt) {
    if (introT >= 1) return;
    introT = Math.min(1, introT + dt / 2.6);
    if (userInteracted) return;   // 用户先动了相机，就别抢镜头
    const e = 1 - Math.pow(1 - introT, 3);
    camera.position.set(0, 46 - 21 * e, 128 - 66 * e);
    controls.target.set(0, 0, 0);
}

function pickNode(cx, cy) {
    if (!camera || !renderer) return null;
    const rect = renderer.domElement.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;

    const halfH = Math.tan((camera.fov * Math.PI) / 360);
    const best = { rec: null, score: Infinity };

    function test(rec) {
        _proj.copy(rec.pos).project(camera);
        if (_proj.z < -1 || _proj.z > 1) return;
        const sx = (_proj.x * 0.5 + 0.5) * rect.width;
        const sy = (-_proj.y * 0.5 + 0.5) * rect.height;
        const dx = sx - cx;
        const dy = sy - cy;
        const distSq = dx * dx + dy * dy;
        const dist = camera.position.distanceTo(rec.pos);
        const pxRadius = (rec.radius / (halfH * Math.max(dist, 0.001))) * (rect.height / 2);
        const tolerance = Math.max(13, pxRadius * 1.5);
        if (distSq > tolerance * tolerance) return;
        const score = Math.sqrt(distSq) - (rec.kind === 'host' ? 3 : 0);
        if (score < best.score) {
            best.score = score;
            best.rec = rec;
        }
    }

    for (let i = 0; i < hostList.length; i++) test(hostList[i]);
    for (let i = 0; i < iocList.length; i++) test(iocList[i]);
    return best.rec;
}

function updateHover() {
    if (!pointerInside || !renderer) {
        if (hoverRec) {
            hoverRec = null;
            showTooltip(null, 0, 0);
            renderer.domElement.style.cursor = 'default';
        }
        return;
    }
    pickFrame = (pickFrame + 1) % 2;
    if (pickFrame !== 0) return;   // 每两帧拾取一次，省一半投影计算

    const rec = pickNode(pointerX, pointerY);
    if (rec !== hoverRec) {
        hoverRec = rec;
        renderer.domElement.style.cursor = rec && rec.kind === 'host' ? 'pointer' : 'default';
    }
    showTooltip(rec, pointerClientX, pointerClientY);
}

function setupInteraction() {
    const dom = renderer.domElement;

    dom.addEventListener('pointerdown', function (ev) {
        pointerHeld = true;
        userInteracted = true;
        downPoint = { x: ev.clientX, y: ev.clientY };
        if (resumeTimer) {
            window.clearTimeout(resumeTimer);
            resumeTimer = 0;
        }
    });

    dom.addEventListener('pointerup', function (ev) {
        if (resumeTimer) window.clearTimeout(resumeTimer);
        // 松手后 1.4 秒再恢复自动旋转（否则一拖完就自己转起来）
        resumeTimer = window.setTimeout(function () {
            pointerHeld = false;
            resumeTimer = 0;
        }, 1400);

        if (!downPoint) return;
        const moved = Math.hypot(ev.clientX - downPoint.x, ev.clientY - downPoint.y);
        downPoint = null;
        if (moved > 6) return;
        if (hoverRec && hoverRec.kind === 'host') {
            window.open('/#hosts', '_blank', 'noopener');
        }
    });

    dom.addEventListener('pointerleave', function () {
        pointerInside = false;
        pointerHeld = false;
    });

    dom.addEventListener('pointermove', function (ev) {
        const rect = dom.getBoundingClientRect();
        pointerX = ev.clientX - rect.left;
        pointerY = ev.clientY - rect.top;
        pointerClientX = ev.clientX;
        pointerClientY = ev.clientY;
        pointerInside = true;
        userInteracted = true;
    });

    dom.addEventListener('wheel', function () {
        userInteracted = true;
    }, { passive: true });
}

/* ==========================================================================
 * 主循环
 * ========================================================================== */

function tick(ts) {
    if (!running) return;
    if (!renderer || !controls) {
        running = false;
        return;
    }
    rafId = window.requestAnimationFrame(tick);

    if (!lastFrameTs) lastFrameTs = ts;
    let dt = (ts - lastFrameTs) / 1000;
    lastFrameTs = ts;
    if (!(dt > 0)) dt = 1 / 60;
    if (dt > 0.05) dt = 0.05;
    sceneTime += dt;

    stepLayout(dt);
    updateIocTargets();
    syncInstances(dt);
    updateEdgeLines();
    updateFlows(dt);
    updateCameraIntro(dt);
    updateHover();

    if (dust) {
        dust.rotation.y += dt * 0.01;
        dust.rotation.x = Math.sin(sceneTime * 0.05) * 0.04;
    }
    if (orbitGroupA) orbitGroupA.rotation.y += dt * 0.16;
    if (orbitGroupB) orbitGroupB.rotation.y -= dt * 0.11;
    if (gridHelper) gridHelper.rotation.y += dt * 0.02;
    if (glowMat) glowMat.uniforms.uStrength.value = 0.42 + Math.sin(sceneTime * 0.7) * 0.06;

    if (hostMat) hostMat.uniforms.uTime.value = sceneTime;
    if (iocMat) iocMat.uniforms.uTime.value = sceneTime;
    if (ringMat) ringMat.uniforms.uTime.value = sceneTime;

    controls.autoRotate = introT >= 1 && !pointerHeld;
    controls.update();
    if (postFxReady && composer) composer.render();
    else renderer.render(scene, camera);
}

function startLoop() {
    if (running || !hasWebGL) return;
    running = true;
    lastFrameTs = 0;
    rafId = window.requestAnimationFrame(tick);
}

function stopLoop() {
    running = false;
    if (rafId) {
        window.cancelAnimationFrame(rafId);
        rafId = 0;
    }
    lastFrameTs = 0;
}

function onResize() {
    if (!renderer || !camera) return;
    const w = window.innerWidth;
    const h = window.innerHeight;
    camera.aspect = w / Math.max(h, 1);
    camera.updateProjectionMatrix();
    const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
    renderer.setPixelRatio(dpr);
    renderer.setSize(w, h);
    if (composer) {
        composer.setPixelRatio(dpr);
        composer.setSize(w, h);
    }
    if (bloomPass) bloomPass.setSize(w, h);
}

function onVisibilityChange() {
    if (document.hidden) stopLoop();
    else startLoop();
}

/* ==========================================================================
 * 时钟与启动
 * ========================================================================== */

function startClock() {
    const box = el('wall-clock');
    if (!box) return;
    function paint() {
        const d = new Date();
        box.textContent = pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    }
    paint();
    window.setInterval(paint, 1000);
}

async function boot() {
    startClock();

    try {
        if (initScene()) {
            setupInteraction();
            await setupPostFx();
            startLoop();
        } else {
            webglMissing = true;
            setStatus('3D 不可用', 'error');
            showNotice('当前环境不支持 WebGL，三维攻防沙盘无法渲染。统计与事件信息仍会持续刷新。');
        }
    } catch (err) {
        // 三维场景挂了也不能拖死数据面板：降级成纯 HTML 展示
        console.warn('[wall] 三维场景初始化失败，已降级为数据展示:', err);
        webglMissing = true;
        hasWebGL = false;
        stopLoop();
        setStatus('3D 异常', 'error');
        showNotice('三维沙盘初始化失败（' + (err && err.message ? err.message : '未知错误')
            + '），已降级为数据展示，统计与事件仍在刷新。');
    }

    refreshGraph().catch(function (err) {
        console.warn('[wall] 首次态势数据加载失败:', err);
    });
    window.setInterval(refreshGraph, REFRESH_MS);
    window.addEventListener('resize', onResize);
    document.addEventListener('visibilitychange', onVisibilityChange);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
} else {
    boot();
}
