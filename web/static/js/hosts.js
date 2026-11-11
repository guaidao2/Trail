/**
 * 主机管理页面：纳管主机的列表、编辑、连通性探测与远程执行。
 *
 * 凭据只写不读：表单提交明文，后端加密存储；列表与详情回显的只有 has_secret 标记。
 */
(function () {
    'use strict';

    let hostsCache = [];
    let currentNodeId = '';

    function tt(key, fallback) {
        if (typeof window.t === 'function') {
            const v = window.t(key);
            if (v && v !== key) return v;
        }
        return fallback || key;
    }

    function el(id) {
        return document.getElementById(id);
    }

    function esc(v) {
        return String(v == null ? '' : v)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function statusBadge(status) {
        const cls = status === 'online' ? 'update-chip-ok'
            : status === 'offline' ? 'update-chip-warn' : '';
        const label = status === 'online' ? tt('hosts.statusOnline', '在线')
            : status === 'offline' ? tt('hosts.statusOffline', '离线')
                : tt('hosts.statusUnknown', '未探测');
        return '<span class="update-chip ' + cls + '">' + esc(label) + '</span>';
    }

    async function apiFetchJSON(url, options) {
        const res = await apiFetch(url, options);
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            throw new Error(data.error || (tt('hosts.requestFailed', '请求失败') + ' (' + res.status + ')'));
        }
        return data;
    }

    async function loadHosts() {
        const tbody = el('hosts-table-body');
        const empty = el('hosts-empty');
        if (!tbody) return;
        const keyword = (el('hosts-search')?.value || '').trim();
        const status = el('hosts-status-filter')?.value || 'all';
        const params = new URLSearchParams({ page_size: '200' });
        if (keyword) params.set('keyword', keyword);
        if (status && status !== 'all') params.set('status', status);

        try {
            const data = await apiFetchJSON('/api/hosts?' + params.toString());
            hostsCache = Array.isArray(data.hosts) ? data.hosts : [];
            tbody.innerHTML = hostsCache.map(renderRow).join('');
            if (empty) empty.style.display = hostsCache.length ? 'none' : '';
        } catch (err) {
            tbody.innerHTML = '<tr><td colspan="7">' + esc(err.message) + '</td></tr>';
            if (empty) empty.style.display = 'none';
        }
    }

    function renderRow(h) {
        const login = esc(h.username || '-') + ' · ' + esc(h.auth_type === 'key'
            ? tt('hosts.authKey', '私钥') : tt('hosts.authPassword', '密码'))
            + (h.has_secret ? '' : ' · ' + esc(tt('hosts.noSecret', '未设凭据')));
        const group = [h.group_name, h.environment].filter(Boolean).join(' / ') || '-';
        const lastCheck = h.last_check_at ? esc(h.last_check_at) : '-';
        return '<tr>' +
            '<td>' + esc(h.name || h.address) + '</td>' +
            '<td><code>' + esc(h.address) + ':' + esc(h.port) + '</code><br/><small>' + esc(h.protocol) + '</small></td>' +
            '<td>' + login + '</td>' +
            '<td>' + esc(group) + '</td>' +
            '<td>' + statusBadge(h.status) + (h.last_error ? '<br/><small title="' + esc(h.last_error) + '">' + esc(h.last_error.slice(0, 40)) + '</small>' : '') + '</td>' +
            '<td>' + lastCheck + '</td>' +
            '<td class="host-actions">' +
            '<button class="btn-secondary btn-sm" data-require-permission="host:read" onclick="probeHost(\'' + esc(h.id) + '\')">' + esc(tt('hosts.probe', '探测')) + '</button> ' +
            '<button class="btn-secondary btn-sm" data-require-permission="host:exec" onclick="openHostTerminal(\'' + esc(h.id) + '\')">' + esc(tt('hosts.terminal', '终端')) + '</button> ' +
            '<button class="btn-secondary btn-sm" data-require-permission="host:write" onclick="showHostModal(\'' + esc(h.id) + '\')">' + esc(tt('common.edit', '编辑')) + '</button> ' +
            '<button class="btn-danger btn-sm" data-require-permission="host:write" onclick="deleteHost(\'' + esc(h.id) + '\')">' + esc(tt('common.delete', '删除')) + '</button>' +
            '</td>' +
            '</tr>';
    }

    function syncHostPortDefault() {
        const proto = el('host-protocol')?.value;
        const portInput = el('host-port');
        if (!portInput) return;
        if (!portInput.value || portInput.value === '22' || portInput.value === '23') {
            portInput.value = proto === 'telnet' ? '23' : '22';
        }
    }

    function syncHostAuthFields() {
        const authType = el('host-auth-type')?.value || 'password';
        const passwordGroup = el('host-password-group');
        const keyGroup = el('host-key-group');
        const passphraseGroup = el('host-passphrase-group');
        const isKey = authType === 'key';
        if (passwordGroup) passwordGroup.style.display = isKey ? 'none' : '';
        if (keyGroup) keyGroup.style.display = isKey ? '' : 'none';
        if (passphraseGroup) passphraseGroup.style.display = isKey ? '' : 'none';
    }

    function showHostModal(id) {
        const editId = id || '';
        const host = hostsCache.find((h) => h.id === editId);
        el('host-edit-id').value = editId;
        el('host-name').value = host ? host.name || '' : '';
        el('host-address').value = host ? host.address || '' : '';
        el('host-protocol').value = host ? host.protocol || 'ssh' : 'ssh';
        el('host-port').value = host ? host.port || 22 : 22;
        el('host-username').value = host ? host.username || '' : '';
        el('host-auth-type').value = host ? host.auth_type || 'password' : 'password';
        el('host-group').value = host ? host.group_name || '' : '';
        el('host-environment').value = host ? host.environment || '' : '';
        el('host-tags').value = host ? host.tags || '' : '';
        el('host-remark').value = host ? host.remark || '' : '';
        el('host-password').value = '';
        el('host-private-key').value = '';
        el('host-passphrase').value = '';
        const title = el('host-modal-title');
        if (title) title.textContent = editId ? tt('hosts.editTitle', '编辑主机') : tt('hosts.add', '纳管主机');
        syncHostAuthFields();
        if (typeof window.openModal === 'function') window.openModal('host-modal');
        else el('host-modal').style.display = 'flex';
    }

    function closeHostModal() {
        if (typeof window.closeModal === 'function') window.closeModal('host-modal');
        else el('host-modal').style.display = 'none';
    }

    async function saveHost() {
        const editId = el('host-edit-id').value;
        const payload = {
            name: el('host-name').value.trim(),
            address: el('host-address').value.trim(),
            protocol: el('host-protocol').value,
            port: parseInt(el('host-port').value, 10) || 0,
            username: el('host-username').value.trim(),
            auth_type: el('host-auth-type').value,
            group_name: el('host-group').value.trim(),
            environment: el('host-environment').value.trim(),
            tags: el('host-tags').value.trim(),
            remark: el('host-remark').value.trim(),
        };
        const password = el('host-password').value;
        const privateKey = el('host-private-key').value.trim();
        const passphrase = el('host-passphrase').value;
        if (payload.auth_type === 'key') {
            if (privateKey) payload.private_key = privateKey;
            if (passphrase) payload.passphrase = passphrase;
        } else if (password) {
            payload.password = password;
        }
        if (!payload.address) {
            showNotification(tt('hosts.addressRequired', '地址不能为空'), 'error');
            return;
        }
        try {
            if (editId) {
                await apiFetchJSON('/api/hosts/' + encodeURIComponent(editId), {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
                });
            } else {
                await apiFetchJSON('/api/hosts', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
                });
            }
            closeHostModal();
            showNotification(tt('hosts.saved', '已保存'), 'success');
            await loadHosts();
        } catch (err) {
            showNotification(err.message, 'error');
        }
    }

    async function deleteHost(id) {
        const host = hostsCache.find((h) => h.id === id);
        const label = host ? (host.name || host.address) : id;
        if (typeof window.confirm === 'function' && !window.confirm(tt('hosts.deleteConfirm', '确认删除该主机？') + '\n' + label)) {
            return;
        }
        try {
            await apiFetchJSON('/api/hosts/' + encodeURIComponent(id), { method: 'DELETE' });
            showNotification(tt('hosts.deleted', '已删除'), 'success');
            await loadHosts();
        } catch (err) {
            showNotification(err.message, 'error');
        }
    }

    async function probeHost(id) {
        try {
            const data = await apiFetchJSON('/api/hosts/' + encodeURIComponent(id) + '/probe', { method: 'POST' });
            const msg = data.online
                ? tt('hosts.probeOnline', '在线') + '：' + (data.os_info || '')
                : tt('hosts.probeOffline', '离线') + '：' + (data.error || '');
            showNotification(msg, data.online ? 'success' : 'error');
            await loadHosts();
        } catch (err) {
            showNotification(err.message, 'error');
        }
    }

    function openHostTerminal(id) {
        const host = hostsCache.find((h) => h.id === id);
        currentNodeId = id;
        const title = el('host-terminal-title');
        if (title) {
            title.textContent = tt('hosts.terminalTitle', '远程终端') + ' · ' + (host ? (host.name || host.address) : id);
        }
        const output = el('host-terminal-output');
        if (output) output.textContent = '';
        const cmd = el('host-terminal-command');
        if (cmd) cmd.value = '';
        const keyEl = el('host-terminal-host-key');
        if (keyEl) keyEl.textContent = (host && host.host_key) ? host.host_key : tt('hosts.hostKeyEmpty', '未记录（首次探测成功后自动信任）');
        if (typeof window.openModal === 'function') window.openModal('host-terminal-modal');
        else el('host-terminal-modal').style.display = 'flex';
    }

    // 主机重装换钥后需要重新信任：清空已固定的指纹，下次探测会重新记录。
    async function resetHostKey() {
        if (!currentNodeId) return;
        if (typeof window.confirm === 'function' && !window.confirm(tt('hosts.trustResetConfirm', '清空已信任的主机密钥指纹？下次探测会重新记录。'))) return;
        try {
            await apiFetchJSON('/api/hosts/' + encodeURIComponent(currentNodeId) + '/host-key', { method: 'DELETE' });
            const host = hostsCache.find((h) => h.id === currentNodeId);
            if (host) host.host_key = '';
            const keyEl = el('host-terminal-host-key');
            if (keyEl) keyEl.textContent = tt('hosts.hostKeyEmpty', '未记录（首次探测成功后自动信任）');
        } catch (err) {
            if (typeof window.showNotification === 'function') window.showNotification(String(err && err.message ? err.message : err), 'error');
        }
    }
    window.resetHostKey = resetHostKey;

    function closeHostTerminal() {
        if (typeof window.closeModal === 'function') window.closeModal('host-terminal-modal');
        else el('host-terminal-modal').style.display = 'none';
    }

    async function runHostCommand() {
        if (!currentNodeId) return;
        const command = (el('host-terminal-command')?.value || '').trim();
        const output = el('host-terminal-output');
        if (!command) return;
        if (output) output.textContent = tt('hosts.running', '执行中…');
        try {
            const data = await apiFetchJSON('/api/hosts/' + encodeURIComponent(currentNodeId) + '/exec', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command }),
            });
            const parts = ['$ ' + command];
            if (data.stdout) parts.push(data.stdout.trimEnd());
            if (data.stderr) parts.push('--- stderr ---\n' + data.stderr.trimEnd());
            parts.push(tt('hosts.exitCode', '退出码') + ': ' + data.exit_code + '（' + data.duration_ms + 'ms）');
            if (output) output.textContent = parts.join('\n');
            await loadHosts();
        } catch (err) {
            if (output) output.textContent = String(err.message);
        }
    }

    async function uploadHostFile() {
        if (!currentNodeId) return;
        const path = (el('host-upload-path')?.value || '').trim();
        const content = el('host-upload-content')?.value || '';
        const mode = (el('host-upload-mode')?.value || '600').trim();
        if (!path) {
            showNotification(tt('hosts.uploadPathRequired', '请填写上传路径'), 'error');
            return;
        }
        try {
            await apiFetchJSON('/api/hosts/' + encodeURIComponent(currentNodeId) + '/upload', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    path,
                    mode,
                    content_base64: btoa(unescape(encodeURIComponent(content))),
                }),
            });
            showNotification(tt('hosts.uploaded', '已上传'), 'success');
        } catch (err) {
            showNotification(err.message, 'error');
        }
    }

    window.loadHosts = loadHosts;
    window.showHostModal = showHostModal;
    window.closeHostModal = closeHostModal;
    window.saveHost = saveHost;
    window.deleteHost = deleteHost;
    window.probeHost = probeHost;
    window.openHostTerminal = openHostTerminal;
    window.closeHostTerminal = closeHostTerminal;
    window.runHostCommand = runHostCommand;
    window.uploadHostFile = uploadHostFile;
    window.syncHostPortDefault = syncHostPortDefault;
    window.syncHostAuthFields = syncHostAuthFields;
    window.initHostsPage = function initHostsPage() {
        loadHosts();
    };
})();
