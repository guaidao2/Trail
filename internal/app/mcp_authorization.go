package app

import (
	"context"
	"fmt"
	"strings"

	"trail/internal/agent"
	"trail/internal/authctx"
	"trail/internal/database"
	"trail/internal/mcp"
	"trail/internal/mcp/builtin"
)

func mcpToolAuthorizer(db *database.DB) func(context.Context, string, map[string]interface{}) error {
	return func(ctx context.Context, toolName string, args map[string]interface{}) error {
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok {
			return fmt.Errorf("missing authenticated principal")
		}
		require := func(permission string) error {
			if !principal.HasPermission(permission) {
				return fmt.Errorf("missing permission %s", permission)
			}
			return nil
		}
		resource := func(permission, resourceType, argument string) error {
			if err := require(permission); err != nil {
				return err
			}
			id := mcpAuthorizationString(args, argument)
			if id == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor(permission), resourceType, id) {
				return fmt.Errorf("no access to %s %s", resourceType, id)
			}
			return nil
		}
		toolExecutionResource := func(permission string) error {
			if err := require(permission); err != nil {
				return err
			}
			id := mcpAuthorizationString(args, "execution_id")
			if id == "" || db == nil || !db.UserCanAccessToolExecution(principal.UserID, principal.ScopeFor(permission), id) {
				return fmt.Errorf("no access to tool execution %s", id)
			}
			return nil
		}

		switch toolName {
		case builtin.ToolRecordVulnerability:
			if err := require("vulnerability:write"); err != nil {
				return err
			}
			conversationID := mcpAuthorizationString(args, "conversation_id")
			if conversationID == "" {
				conversationID = mcpAuthorizationConversationID(ctx)
			}
			if conversationID == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("vulnerability:write"), "conversation", conversationID) {
				return fmt.Errorf("no access to conversation %s", conversationID)
			}
			return nil
		case builtin.ToolListVulnerabilities:
			if err := require("vulnerability:read"); err != nil {
				return err
			}
			conversationID := mcpAuthorizationConversationID(ctx)
			if conversationID == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("vulnerability:read"), "conversation", conversationID) {
				return fmt.Errorf("no access to conversation %s", conversationID)
			}
			return nil
		case builtin.ToolGetVulnerability, builtin.ToolUpdateVulnerabilityStatus:
			permission := "vulnerability:read"
			if toolName == builtin.ToolUpdateVulnerabilityStatus {
				permission = "vulnerability:write"
			}
			if err := require(permission); err != nil {
				return err
			}
			id := mcpAuthorizationString(args, "id")
			if db == nil || id == "" || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor(permission), "vulnerability", id) {
				return fmt.Errorf("no access to vulnerability %s", id)
			}
			convID := mcpAuthorizationConversationID(ctx)
			if r, err := db.GetVulnerabilityRetest(convID); err != nil {
				return err
			} else if r != nil {
				if r.VulnerabilityID != id || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor(permission), "conversation", convID) {
					return fmt.Errorf("no access to retest vulnerability %s", id)
				}
				v, err := db.GetVulnerability(id)
				if err != nil {
					return err
				}
				if !canAccessVulnerabilityForRetest(db, v, convID) {
					return fmt.Errorf("retest conversation no longer matches vulnerability %s", id)
				}
				return nil
			}
			return nil
		case builtin.ToolQueryAssets:
			return require("asset:read")
		case builtin.ToolGetAsset:
			return resource("asset:read", "asset", "id")
		case builtin.ToolCreateAsset:
			return require("asset:write")
		case builtin.ToolUpdateAsset, builtin.ToolCompleteAssetScan:
			if err := resource("asset:write", "asset", "id"); err != nil {
				return err
			}
			if toolName == builtin.ToolCompleteAssetScan {
				conversationID := mcpAuthorizationConversationID(ctx)
				if conversationID == "" || db == nil || !db.UserCanAccessResource(principal.UserID, principal.ScopeFor("asset:write"), "conversation", conversationID) {
					return fmt.Errorf("no access to conversation %s", conversationID)
				}
			}
			return nil
		case builtin.ToolHostList, builtin.ToolHostGet, builtin.ToolHostProbe, builtin.ToolHostInspect:
			return require("host:read")
		case builtin.ToolHostExec, builtin.ToolHostUpload, builtin.ToolHostDownload:
			return require("host:exec")
		case builtin.ToolDeleteAsset:
			return resource("asset:delete", "asset", "id")
		case builtin.ToolListKnowledgeRiskTypes, builtin.ToolSearchKnowledgeBase:
			return require("knowledge:read")
		case builtin.ToolAnalyzeImage:
			return require("agent:execute")
		case builtin.ToolGetToolExecution, builtin.ToolWaitToolExecution:
			return toolExecutionResource("monitor:read")
		case builtin.ToolCancelToolExecution:
			return toolExecutionResource("monitor:write")
		case builtin.ToolBatchTaskList:
			return require("tasks:read")
		case builtin.ToolBatchTaskGet:
			return resource("tasks:read", "batch_task", "queue_id")
		case builtin.ToolBatchTaskCreate:
			return require("tasks:write")
		case builtin.ToolBatchTaskDelete, builtin.ToolBatchTaskRemove:
			return resource("tasks:delete", "batch_task", "queue_id")
		case builtin.ToolBatchTaskStart, builtin.ToolBatchTaskRerun, builtin.ToolBatchTaskPause,
			builtin.ToolBatchTaskUpdateMetadata, builtin.ToolBatchTaskUpdateSchedule,
			builtin.ToolBatchTaskScheduleEnabled, builtin.ToolBatchTaskAdd, builtin.ToolBatchTaskUpdate:
			return resource("tasks:write", "batch_task", "queue_id")
		default:
			if builtin.IsBuiltinTool(toolName) {
				return fmt.Errorf("no authorization policy registered for builtin tool %s", toolName)
			}
			if principal.HasPermission("agent:local-execute") {
				return nil
			}
			return fmt.Errorf("missing agent:local-execute")
		}
	}
}

func externalMCPToolAuthorizer() func(context.Context, string, map[string]interface{}) error {
	return func(ctx context.Context, toolName string, _ map[string]interface{}) error {
		principal, ok := authctx.PrincipalFromContext(ctx)
		if !ok {
			return fmt.Errorf("missing authenticated principal")
		}
		if !principal.HasPermission("mcp:external:execute") {
			return fmt.Errorf("missing permission mcp:external:execute")
		}
		if principal.ScopeFor("mcp:external:execute") != database.RBACScopeAll {
			return fmt.Errorf("external MCP invocation requires global scope")
		}
		if strings.TrimSpace(toolName) == "" {
			return fmt.Errorf("missing external tool name")
		}
		return nil
	}
}

func mcpAuthorizationConversationID(ctx context.Context) string {
	if id := strings.TrimSpace(agent.ConversationIDFromContext(ctx)); id != "" {
		return id
	}
	return strings.TrimSpace(mcp.MCPConversationIDFromContext(ctx))
}

func mcpAuthorizationString(args map[string]interface{}, key string) string {
	value, _ := args[key].(string)
	return strings.TrimSpace(value)
}
