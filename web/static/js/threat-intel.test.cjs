const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'threat-intel.js'), 'utf8');
const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
const LOCALES = ['zh-CN', 'en-US', 'ru-RU', 'ar-SA'];

function threatIntelDict(locale) {
    const all = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n', locale + '.json'), 'utf8'));
    return all.threatIntel || {};
}

// tt() 的 key 与 HTML 的 data-i18n 都要能在四语言里取到，
// 缺键不会报错、只会静默回退中文，页面上看着"少翻译"却查不出原因。
test('every threatIntel i18n key used by the page exists in all four locales', () => {
    const jsKeys = [...source.matchAll(/tt\('([^']+)'/g)]
        .map(m => m[1])
        .filter(k => k.startsWith('threatIntel.'));
    const htmlKeys = [...template.matchAll(/data-i18n="(threatIntel\.[A-Za-z]+)"/g)].map(m => m[1]);
    const verdictKeys = [...source.matchAll(/key: '(threatIntel\.[A-Za-z]+)'/g)].map(m => m[1]);
    const keys = new Set([...jsKeys, ...htmlKeys, ...verdictKeys]);
    assert.ok(keys.size > 20, '应识别到足够多的键，实际 ' + keys.size);

    for (const locale of LOCALES) {
        const dict = threatIntelDict(locale);
        for (const key of keys) {
            const leaf = key.slice('threatIntel.'.length);
            assert.ok(
                Object.prototype.hasOwnProperty.call(dict, leaf),
                `${locale} 缺少 ${key}`
            );
            assert.notEqual(String(dict[leaf]).trim(), '', `${locale} 的 ${key} 不能为空`);
        }
    }
});

test('verdict badge covers every verdict the backend can return', () => {
    // 后端可能给的判定值：恶意 / 可疑 / 干净 / 暴露面 / 未知。
    for (const verdict of ['malicious', 'suspicious', 'clean', 'exposure', 'unknown']) {
        assert.match(source, new RegExp(verdict + ':'), `缺少 ${verdict} 的展示映射`);
    }
});

test('feed table colspan matches the six rendered columns', () => {
    const headers = (template.match(/<th data-i18n="threatIntel\.col[A-Za-z]+"/g) || []).length;
    assert.equal(headers, 6, '订阅表应有 6 列');
    for (const m of source.matchAll(/colspan="(\d+)"/g)) {
        assert.equal(m[1], '6', '空态/加载行的 colspan 必须是 6');
    }
});

test('adopt button requires both permissions the backend enforces', () => {
    // 路由要 threatintel:write，handler 还要 ioc:write，缺一个就是 403。
    assert.match(source, /hasPermission\('ioc:write'\)/);
    assert.match(source, /hasPermission\('threatintel:write'\)/);
});

test('external strings are escaped before entering innerHTML', () => {
    // 摘要、标签、指标值全部来自外部源，必须经 esc()。
    // 只检查调用前缀，不要求整段表达式完全一致（有 `|| '-'` 这类兜底）。
    for (const field of ['r.summary', 'tag', 'it.normalized', 'it.malware', 's.source']) {
        assert.ok(
            source.includes(`esc(${field}`),
            `${field} 应经过 esc()`
        );
    }
});

test('hash 过滤选项与后端展开保持一致', () => {
    // DB 层把 type=hash 展开成 md5/sha1/sha256，页面上要有对应选项，
    // 否则用户选 hash 时看到的和实际查询口径对不上。
    assert.match(template, /<option value="hash"/);
    assert.match(template, /<option value="md5"/);
    assert.match(template, /<option value="sha1"/);
    assert.match(template, /<option value="sha256"/);
});

// 订阅列表的分页必须和其它页面用同一套组件与文案，不能再回到手搓版本。
test('feed pagination reuses the shared pagination component', () => {
    assert.match(source, /class="pagination"/, '应使用公共 .pagination 结构');
    assert.match(source, /class="pagination-info"/);
    assert.match(source, /class="pagination-page-size"/);
    assert.match(source, /class="pagination-controls"/);
    // 四个按钮 + 每页条数选项，顺序与 ioc/vuln-intel/memory 三页一致。
    for (const label of ['skillsPage.firstPage', 'skillsPage.prevPage', 'skillsPage.nextPage', 'skillsPage.lastPage']) {
        assert.ok(source.includes(label), `分页按钮应复用 ${label} 文案`);
    }
    assert.match(source, /\[10, 20, 50, 100\]/, '每页条数选项应为 10/20/50/100');
    // 页码信息形如 "1-20 / N"，用 start + '-' + end + ' / ' + totalCount 拼出来。
    assert.match(source, /start \+ '-' \+ end \+ ' \/ ' \+ totalCount/);
});

test('feed pagination state matches other pages', () => {
    assert.match(source, /let currentPage = 1;/);
    assert.match(source, /let pageSize = 20;/);
    assert.match(source, /let totalCount = 0;/);
    assert.match(source, /window\.threatIntelGotoPage = threatIntelGotoPage;/);
    assert.match(source, /window\.threatIntelChangePageSize = threatIntelChangePageSize;/);
});
