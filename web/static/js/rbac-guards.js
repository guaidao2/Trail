/**
 * 全局写操作权限守卫：为各页面 onclick 绑定的 window 方法统一包一层 requirePermission。
 * 在全部业务脚本加载完成后执行（见 index.html 引用顺序）。
 */
(function () {
    'use strict';

    const GLOBAL_WRITE_HANDLER_PERMISSIONS = {
        // 对话
        sendMessage: 'chat:write',
        startNewConversation: 'chat:write',
        deleteConversation: 'chat:delete',
        deleteConversationTurnFromUI: 'chat:delete',
        deleteConversationFromContext: 'chat:delete',
        showBatchManageModal: 'chat:delete',
        deleteSelectedConversations: 'chat:delete',
        renameConversation: 'chat:write',
        pinConversation: 'chat:write',

        // 人机协同
        applyHitlSidebarConfig: 'hitl:write',
        saveHitlPageWhitelist: 'hitl:write',
        saveHitlAuditStrategy: 'hitl:write',
        saveHitlConversationConfig: 'hitl:write',
        submitHitlDecision: 'hitl:write',
        submitHitlDecisionWithPayload: 'hitl:write',
        submitWorkflowHitlDecisionFromPage: 'hitl:write',
        submitWorkflowHitlDecision: 'hitl:write',
        dismissHitlItem: 'hitl:write',
        batchDeleteHitlLogs: 'hitl:write',
        clearHitlLogs: 'hitl:write',
        createVulnerabilityFromCurrentFact: 'vulnerability:write',

        // 漏洞
        showAddVulnerabilityModal: 'vulnerability:write',
        saveVulnerability: 'vulnerability:write',
        deleteVulnerability: 'vulnerability:delete',
        batchDeleteVulnerabilityReports: 'vulnerability:delete',
        exportVulnerabilityReports: 'vulnerability:read',
        changeVulnerabilityStatus: 'vulnerability:write',

        // 角色 / Skills / Agents
        showAddRoleModal: 'roles:write',
        saveRole: 'roles:write',
        deleteRole: 'roles:delete',
        showAddSkillModal: 'skills:write',
        saveSkill: 'skills:write',
        deleteSkill: 'skills:delete',
        showAddMarkdownAgentModal: 'agents:write',
        saveMarkdownAgent: 'agents:write',
        deleteMarkdownAgent: 'agents:delete',

        // 知识库
        buildKnowledgeIndex: 'knowledge:write',
        rebuildKnowledgeIndexFull: 'knowledge:write',
        showAddKnowledgeItemModal: 'knowledge:write',
        saveKnowledgeItem: 'knowledge:write',
        editKnowledgeItem: 'knowledge:write',
        deleteKnowledgeItem: 'knowledge:delete',
        deleteRetrievalLog: 'knowledge:delete',

        // 设置 / MCP
        saveToolGuardConfig: 'config:write',
        addToolGuardRule: 'config:write',
        resetToolGuardConfig: 'config:write',
        changeToolGuardEnabled: 'config:write',
        applySettings: 'config:write',
        saveToolsConfig: 'config:write',
        saveExternalMCP: 'mcp:write',
        showAddExternalMCPModal: 'mcp:write',
        deleteExternalMCP: 'mcp:write',
        toggleExternalMCP: 'mcp:write',
        changePassword: 'auth:self',
        testOpenAIConnection: 'config:write',
        testVisionConnection: 'config:write',
        testHitlAuditModelConnection: 'config:write',
        submitMcpToolAbortModal: 'monitor:write',
        cancelMCPToolExecution: 'monitor:write',

        // FOFA / 信息收集
        submitFofaSearch: 'fofa:execute',
        scanFofaRow: 'fofa:execute',
        batchScanSelectedFofaRows: 'fofa:execute',
        exportFofaResults: 'fofa:execute',
        importSelectedFofaAssets: 'asset:write',
        importFofaRowAsset: 'asset:write',
        openAssetImport: 'asset:write',
        submitAssetImport: 'asset:write',
        saveAsset: 'asset:write',
        deleteAsset: 'asset:delete',

        // 任务队列
        showBatchImportModal: 'tasks:write',
        deleteBatchQueue: 'tasks:delete',
        deleteBatchQueueFromList: 'tasks:delete',
        createBatchQueue: 'tasks:write',
        saveAddBatchTask: 'tasks:write',
        saveInlineTask: 'tasks:write',
        deleteBatchTask: 'tasks:delete',
        deleteBatchTaskFromElement: 'tasks:delete',
        saveInlineTitle: 'tasks:write',
        saveInlineRole: 'tasks:write',
        saveInlineAgentMode: 'tasks:write',
        saveInlineConcurrency: 'tasks:write',
        saveInlineSchedule: 'tasks:write',
        startBatchQueue: 'tasks:write',
        pauseBatchQueue: 'tasks:write',
        rerunBatchQueue: 'tasks:write',
        runSingleBatchTask: 'tasks:write',
        editBatchTaskFromElement: 'tasks:write',
        batchCancelTasks: 'tasks:write',
        cancelTask: 'tasks:write',
        cancelActiveTask: 'tasks:write',
        cancelProgressTask: 'tasks:write',

        // 工作流
        saveWorkflowDraft: 'workflow:write',
        applyWorkflowMetaModal: 'workflow:write',
        deleteCurrentWorkflow: 'workflow:delete',
        deleteWorkflowSelection: 'workflow:delete',
        dryRunWorkflowDraft: 'workflow:execute',
        toggleWorkflowEnabled: 'workflow:write',
        addWorkflowNodeFromPalette: 'workflow:write',
        toggleWorkflowConnectMode: 'workflow:write',
        addWorkflowCustomField: 'workflow:write',

        // 文件管理
        saveChatFilesEdit: 'files:write',
        deleteChatFile: 'files:delete',
        deleteChatFileIdx: 'files:delete',
        deleteChatFolderFromBrowse: 'files:delete',
        submitChatFilesRename: 'files:write',
        submitChatFilesMkdir: 'files:write',
        onChatFilesUploadPick: 'files:write',

        // 监控
        deleteExecution: 'monitor:delete',
        batchDeleteExecutions: 'monitor:delete',

        // 通知
        markAllNotificationsSeen: 'notification:write',

        // RBAC
        saveRbacUser: 'rbac:write',
        deleteSelectedRbacUser: 'rbac:write',
        saveRbacRole: 'rbac:write',
        deleteRbacRole: 'rbac:write',
        createRbacAssignment: 'rbac:write',
        deleteRbacAssignment: 'rbac:write',
        saveSelectedUserRoles: 'rbac:write',

        // 主机纳管
        showHostModal: 'host:write',
        saveHost: 'host:write',
        deleteHost: 'host:write',
        probeHost: 'host:read',
        resetHostKey: 'host:write',
        openHostTerminal: 'host:exec',
        runHostCommand: 'host:exec',
        uploadHostFile: 'host:exec',

        // 机器人
        openRobotCreateModal: 'robot:write',
        openRobotEditor: 'robot:write',
        startWechatRobotBind: 'robot:write',
        submitWechatVerifyCode: 'robot:write',

        // 审计
        exportAuditLogs: 'audit:read',
        exportAuditLogsCsv: 'audit:read',
        runAuditExport: 'audit:read',

        // Agent 中断
        submitUserInterruptContinue: 'agent:execute',
        submitUserInterruptHardCancel: 'agent:execute',

        // 终端（多会话）
        addTerminalTab: 'terminal:execute',
        removeTerminalTab: 'terminal:execute',
    };

    const NAMESPACE_WRITE_HANDLER_PERMISSIONS = {
    };

    function wrapHandlerWithPermission(fn, permission) {
        if (typeof fn !== 'function') return fn;
        if (fn.__rbacGuarded) return fn;
        const wrapped = function rbacGuardedHandler(...args) {
            if (typeof requirePermission === 'function' && !requirePermission(permission)) {
                return undefined;
            }
            return fn.apply(this, args);
        };
        wrapped.__rbacGuarded = true;
        wrapped.__rbacOriginal = fn;
        return wrapped;
    }

    function installWriteHandlerGuards() {
        Object.entries(GLOBAL_WRITE_HANDLER_PERMISSIONS).forEach(([name, permission]) => {
            if (typeof window[name] === 'function') {
                window[name] = wrapHandlerWithPermission(window[name], permission);
            }
        });
        Object.entries(NAMESPACE_WRITE_HANDLER_PERMISSIONS).forEach(([ns, methods]) => {
            const root = window[ns];
            if (!root || typeof root !== 'object') return;
            Object.entries(methods).forEach(([method, permission]) => {
                if (typeof root[method] === 'function') {
                    root[method] = wrapHandlerWithPermission(root[method], permission);
                }
            });
        });
    }

    window.installWriteHandlerGuards = installWriteHandlerGuards;
    installWriteHandlerGuards();
})();
