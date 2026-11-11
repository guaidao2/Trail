const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const hosts = fs.readFileSync('web/static/js/hosts.js', 'utf8');
const guards = fs.readFileSync('web/static/js/rbac-guards.js', 'utf8');

test('主机管理前端与后端使用同一套 host 权限', () => {
    // 探测是只读：按钮与守卫都必须是 host:read，否则只读角色看不到/点不了。
    assert.match(hosts, /data-require-permission="host:read" onclick="probeHost\(/);
    assert.match(guards, /probeHost:\s*'host:read'/);
    // 终端/命令/上传属于执行类。
    assert.match(hosts, /data-require-permission="host:exec" onclick="openHostTerminal\(/);
    assert.match(guards, /runHostCommand:\s*'host:exec'/);
    assert.match(guards, /uploadHostFile:\s*'host:exec'/);
});

test('重新信任密钥调用带 /api 前缀的真实接口', () => {
    // 少写 /api 会 404，而 apiFetch 只在 401 抛错 → 界面会误报成功。
    assert.match(hosts, /apiFetchJSON\('\/api\/hosts\/' \+ encodeURIComponent\(currentNodeId\) \+ '\/host-key'/);
    assert.match(guards, /resetHostKey:\s*'host:write'/);
});
