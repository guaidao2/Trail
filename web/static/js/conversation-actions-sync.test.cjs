const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');
const template = fs.readFileSync('web/templates/index.html', 'utf8');

function functionSource(source, name, nextName) {
    const start = source.indexOf(`function ${name}(`);
    const end = nextName ? source.indexOf(`function ${nextName}(`, start) : source.length;
    assert.notEqual(start, -1, `${name} should exist`);
    if (nextName) {
        assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    }
    return source.slice(start, end);
}

test('对话侧栏只保留最近对话区域', () => {
    assert.doesNotMatch(template, /class="conversation-groups-section"/);
    assert.doesNotMatch(template, /id="conversation-groups-list"/);
});

test('对话三点菜单仍绑定打开上下文菜单', () => {
    const itemSource = functionSource(chat, 'createConversationListItemWithMenu', 'openConversationContextMenuForId');
    const menuSource = functionSource(chat, 'showConversationContextMenu', 'ensureConversationRenameModal');

    assert.match(itemSource, /menuBtn\.onclick = \(e\) => openConversationContextMenuForId\(e, conversation\.id, conversation\.title \|\| ''\)/);
    assert.match(menuSource, /const menu = document\.getElementById\('conversation-context-menu'\)/);
    assert.match(menuSource, /menu\.style\.display = 'block'/);
    assert.match(chat, /function clearDownloadMarkdownSubmenuHideTimeout\(/);
    assert.match(chat, /function handleDownloadMarkdownSubmenuEnter\(/);
    assert.match(chat, /function handleDownloadMarkdownSubmenuLeave\(/);
    assert.match(chat, /function hideDownloadMarkdownSubmenu\(/);
});
