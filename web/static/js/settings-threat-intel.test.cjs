const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const template = fs.readFileSync(path.join(__dirname, '../../templates/index.html'), 'utf8');
const settings = fs.readFileSync(path.join(__dirname, 'settings.js'), 'utf8');
const LOCALES = ['zh-CN', 'en-US', 'ru-RU', 'ar-SA'];

// 设置页的威胁情报区块：控件、字段名、i18n 键必须和后端结构对得上，
// 少一个 id 就会表现成"保存了但没生效"，而且不会有任何报错。

test('settings page renders the threat intel section with every control', () => {
    assert.match(template, /id="settings-section-threat-intel"/);
    assert.match(template, /data-section="threat-intel"/);
    for (const id of [
        'threat-intel-enabled',
        'threat-intel-proxy',
        'threat-intel-timeout',
        'threat-intel-feed-sync-interval',
        'threat-intel-feed-ttl-days',
        'threat-intel-cache-ttl-seconds',
        'threat-intel-abuseipdb-key',
        'threat-intel-virustotal-key',
        'threat-intel-urlhaus-key',
        'threat-intel-threatfox-key',
    ]) {
        assert.ok(template.includes(`id="${id}"`), `缺少控件 ${id}`);
    }
});

test('disabled-source checkboxes cover exactly the registered sources', () => {
    const values = [...template.matchAll(/class="threat-intel-disabled" value="([a-z_]+)"/g)].map(m => m[1]);
    assert.deepEqual(values.sort(), [
        'abuseipdb', 'feodo', 'greynoise', 'internetdb', 'otx',
        'spamhaus_drop', 'threatfox', 'urlhaus', 'virustotal',
    ].sort());
});

test('settings.js wires load and save for the threat intel section', () => {
    assert.match(settings, /function applyThreatIntelSettings\(/);
    assert.match(settings, /function saveThreatIntelSettings\(/);
    assert.match(settings, /window\.applyThreatIntelSettings = applyThreatIntelSettings;/);
    assert.match(settings, /window\.saveThreatIntelSettings = saveThreatIntelSettings;/);
    // 加载配置时必须回填，否则打开设置页看到的是空表单。
    assert.match(settings, /applyThreatIntelSettings\(currentConfig && currentConfig\.threat_intel\)/);
    // 保存时必须提交 threat_intel 段，而不是混进别的段。
    assert.match(settings, /payload\.threat_intel\.feed_ttl_days/);
    assert.match(settings, /payload\.threat_intel\.cache_ttl_seconds/);
});

test('save payload uses the same key names the backend expects', () => {
    for (const field of [
        'enabled', 'proxy', 'timeout', 'feed_sync_interval',
        'abuseipdb_key', 'virustotal_key', 'urlhaus_key', 'threatfox_key',
        'disabled_sources',
    ]) {
        assert.ok(settings.includes(field + ':'), `payload 缺少字段 ${field}`);
    }
});

test('every settingsThreatIntel i18n key exists in all four locales', () => {
    const keys = new Set(
        [...template.matchAll(/data-i18n="(settingsThreatIntel\.[A-Za-z]+)"/g)].map(m => m[1])
    );
    assert.ok(keys.size >= 15, '应识别到足够多的键，实际 ' + keys.size);
    for (const locale of LOCALES) {
        const all = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n', locale + '.json'), 'utf8'));
        const dict = all.settingsThreatIntel || {};
        const nav = all.settings && all.settings.nav ? all.settings.nav : {};
        for (const key of keys) {
            const leaf = key.slice('settingsThreatIntel.'.length);
            assert.ok(Object.prototype.hasOwnProperty.call(dict, leaf), `${locale} 缺少 ${key}`);
            assert.notEqual(String(dict[leaf]).trim(), '', `${locale} 的 ${key} 不能为空`);
        }
        assert.ok(Object.prototype.hasOwnProperty.call(nav, 'threatIntel'), `${locale} 缺少 settings.nav.threatIntel`);
    }
});

// 代理地址与 API Key 默认遮住、可点眼睛看明文。
// 代理常写成 http://user:pass@host，直接明文显示容易在共享屏幕上泄露。
test('proxy and key inputs can toggle between masked and plaintext', () => {
    const fields = [...template.matchAll(/class="secret-field"[\s\S]{0,600}?id="([a-z-]+)"/g)].map(m => m[1]);
    assert.deepEqual(fields.sort(), [
        'threat-intel-abuseipdb-key',
        'threat-intel-proxy',
        'threat-intel-threatfox-key',
        'threat-intel-urlhaus-key',
        'threat-intel-virustotal-key',
        'vuln-intel-proxy',
    ].sort());

    // 每个被遮住的字段都要有对应的切换按钮，否则那个框永远看不了明文。
    for (const id of fields) {
        assert.ok(
            template.includes(`toggleSecretVisibility('${id}'`),
            `${id} 缺少显隐切换按钮`
        );
    }
    // 默认必须是 password，不能在 HTML 里就写出明文。
    for (const id of fields) {
        const re = new RegExp(`<input type="password" id="${id}"`);
        assert.ok(re.test(template), `${id} 默认应为 password 类型`);
    }
    assert.match(settings, /function toggleSecretVisibility\(/);
    assert.match(settings, /window\.toggleSecretVisibility = toggleSecretVisibility;/);
});

test('toggle button labels are translated in all four locales', () => {
    for (const locale of LOCALES) {
        const all = JSON.parse(fs.readFileSync(path.join(__dirname, '../i18n', locale + '.json'), 'utf8'));
        const common = all.common || {};
        assert.ok(common.showSecret, `${locale} 缺少 common.showSecret`);
        assert.ok(common.hideSecret, `${locale} 缺少 common.hideSecret`);
    }
});
