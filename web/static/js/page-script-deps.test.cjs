/*
 * 页面脚本依赖的防回归测试。
 *
 * 背景（2026-11-11）：清理重复 <script> 标签时把 vendor/cytoscape.min.js 一起删掉了，
 * 而 workflows.js 依赖全局 cytoscape —— initCy() 静默 return，工作流页的列表永远停在
 * 「加载中…」。这类"页面依赖某个全局，但 index.html 不再加载它"的断链，语法检查和
 * 组件级单测都看不出来，只能在模板层守护。
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..', '..');
const template = fs.readFileSync(path.join(root, 'web/templates/index.html'), 'utf8');

function scriptIndex(src) {
    return template.indexOf(`src="${src}"`);
}

test('index.html 引用的每个本地脚本都真实存在', () => {
    const refs = [...template.matchAll(/<script[^>]+src="(\/static\/[^"?]+)[^"]*"/g)].map((m) => m[1]);
    assert.ok(refs.length > 10, `脚本数量异常：${refs.length}`);

    const missing = refs.filter((ref) => !fs.existsSync(path.join(root, 'web', ref.replace(/^\/static\//, 'static/'))));
    assert.deepEqual(missing, [], `index.html 引用了不存在的脚本：${missing.join(', ')}`);
});

test('工作流页依赖的 cytoscape 在 workflows.js 之前加载', () => {
    const vendor = scriptIndex('/static/vendor/cytoscape.min.js');
    const page = scriptIndex('/static/js/workflows.js');

    assert.notEqual(vendor, -1, 'index.html 没有加载 /static/vendor/cytoscape.min.js');
    assert.notEqual(page, -1, 'index.html 没有加载 /static/js/workflows.js');
    assert.ok(vendor < page, 'cytoscape 必须在 workflows.js 之前加载，否则 initCy() 会静默跳过');
});

test('工作流页仍然声明它需要的全局依赖', () => {
    const workflows = fs.readFileSync(path.join(root, 'web/static/js/workflows.js'), 'utf8');
    assert.match(workflows, /typeof cytoscape !== 'function'/, 'workflows.js 应保留对 cytoscape 的存在性检查');
});

test('refreshWorkflows 在空列表分支也必须重绘列表', () => {
    const workflows = fs.readFileSync(path.join(root, 'web/static/js/workflows.js'), 'utf8');
    assert.match(
        workflows,
        /newWorkflowDraft\(\{ openMeta: false \}\);\s*\}\s*renderWorkflowList\(\);/,
        '空列表分支不能提前 return，否则「加载中…」永远不被替换',
    );
});
