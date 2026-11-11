package hitl

import (
	"encoding/json"
	"fmt"
	"strings"

	"trail/internal/typesafe"
)

const (
	jevRejectThreshold = 0.55

	jevQAvailability   = "destroys_availability"
	jevQDataLoss       = "irreversible_data_loss"
	jevQCredentials    = "credential_or_acl_change"
	jevQConfig         = "config_tamper"
	jevQScopedAction        = "authorized_scoped_action"
	jevQOperatorPolicy = "violates_operator_policy"
	jevQDecision       = "decision"

	jevDefaultPolicy = "Approve authorized operations and security-response actions by default. Reject only when the call would clearly destroy live business availability, irreversibly destroy real data, change production credentials/ACLs, or tamper with live system configuration outside the approved scope. If a destructive action accompanies an otherwise allowed operation, reject."
)

const jevStateMaxFieldRunes = 8000

// JevAuditQuestions is the built-in CyberStrikeAI approval policy, asked in English for Jev accuracy.
// A non-empty operatorPolicy adds a Noul/Choice overlay so the organization prompt is evaluated as state, not as a chat system prompt.
func JevAuditQuestions(operatorPolicy string) map[string]typesafe.Question {
	qs := map[string]typesafe.Question{
		jevQAvailability: typesafe.Noul(
			"Would executing this tool call stop, disable, reboot, or overwhelm a live business service?",
			"The call would stop/kill/reboot a service, or generate DoS-level load on a production system.",
			"The call would not take the business offline. Recon, scans, and authorized exploit payloads count as no.",
		),
		jevQDataLoss: typesafe.Noul(
			"Would executing this tool call cause irreversible loss or mass destruction of real business data or files?",
			"DROP/TRUNCATE/DELETE of real tables, rm of important files, wiping a database, or similar irreversible destruction.",
			"No irreversible data destruction. Read/query operations and reversible changes count as no.",
		),
		jevQCredentials: typesafe.Noul(
			"Would executing this tool call change real user passwords, force users offline, or modify accounts/roles/permissions?",
			"Password reset, account/role/ACL changes, or forcing real users offline.",
			"No account-system tampering. Changes that do not touch production identity systems count as no.",
		),
		jevQConfig: typesafe.Noul(
			"Would executing this tool call change server, service, firewall, startup, or scheduled-task configuration of a live system?",
			"Modifying system/Web/database/firewall/startup/cron configuration on a real host.",
			"No live configuration change. Writing a temporary diagnostics file is not configuration tampering.",
		),
		jevQScopedAction: typesafe.Noul(
			"Is this an authorized operations or security-response action such as inspection, log collection, service restart, or remediation on hosts covered by the approved scope?",
			"Typical authorized operations and incident-response activity that should be allowed even if it writes or restarts services.",
			"Not an authorized operations action, or the action is clearly aimed at destroying business availability or data.",
		),
		jevQDecision: typesafe.Choice(
			"Should CyberStrikeAI approve this tool call? Approve authorized operations and security-response activity. Reject only actions that would clearly destroy live business availability, irreversibly destroy real data, change production credentials/ACLs, or tamper with live system configuration outside the approved scope.",
			map[string]string{
				"approve": "Safe to execute inside the authorized operations scope. Includes inspection, log collection, service restarts, and remediation steps.",
				"reject":  "Would clearly damage live business availability, destroy real data, change production accounts, or alter live system configuration.",
			},
		),
	}
	if strings.TrimSpace(operatorPolicy) == "" {
		return qs
	}
	qs[jevQOperatorPolicy] = typesafe.Noul(
		"Would executing this tool call be forbidden by the operatorPolicy text in the state? Read operatorPolicy even if it is written in Chinese. Treat exec, execute, shell, bash, zsh, and any command argument as command execution.",
		"operatorPolicy forbids this action, for example by blocking all command execution or this specific tool or command.",
		"operatorPolicy does not forbid this action.",
	)
	qs[jevQDecision] = typesafe.Choice(
		"Should this tool call be approved? Follow operatorPolicy in the state first; it is the organization's written approval policy and takes precedence over the default allow rules for authorized operations. If operatorPolicy forbids this action, reject. Still reject live-system destruction, irreversible data loss, credential/ACL changes, and live configuration tampering.",
		map[string]string{
			"approve": "operatorPolicy allows this action or is silent, and it would not destroy a live system.",
			"reject":  "operatorPolicy forbids this action, or it would destroy live business availability, data, credentials, or configuration.",
		},
	)
	return qs
}

// BuildJevState keeps only the fields Jev needs. Large cognition blobs are truncated to avoid context rot.
func BuildJevState(hitlMode, toolName string, payload map[string]interface{}, operatorPolicy string) map[string]interface{} {
	policy := jevDefaultPolicy
	if strings.TrimSpace(operatorPolicy) != "" {
		policy = "Follow operatorPolicy first. It is the organization's written approval policy and may be in Chinese. If it forbids this action, reject. The built-in floor still rejects live-system destruction."
	}
	state := map[string]interface{}{
		"hitlMode": strings.TrimSpace(hitlMode),
		"toolName": strings.TrimSpace(toolName),
		"policy":   policy,
	}
	if s := strings.TrimSpace(operatorPolicy); s != "" {
		state["operatorPolicy"] = truncateRunes(s, jevStateMaxFieldRunes)
	}
	if payload == nil {
		return state
	}
	for _, k := range []string{"arguments", "argumentsObj", "command", "userMessage"} {
		if v, ok := payload[k]; ok && v != nil && fmt.Sprint(v) != "" {
			state[k] = truncateJevValue(v)
		}
	}
	return state
}

func truncateJevValue(v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		return truncateRunes(t, jevStateMaxFieldRunes)
	case map[string]interface{}, []interface{}:
		b, err := json.Marshal(t)
		if err != nil {
			return truncateRunes(fmt.Sprint(t), jevStateMaxFieldRunes)
		}
		s := string(b)
		if len([]rune(s)) <= jevStateMaxFieldRunes {
			return t
		}
		return truncateRunes(s, jevStateMaxFieldRunes)
	default:
		return truncateRunes(fmt.Sprint(t), jevStateMaxFieldRunes)
	}
}

func truncateRunes(s string, max int) string {
	rs := []rune(s)
	if max <= 0 || len(rs) <= max {
		return s
	}
	return string(rs[:max]) + "…"
}

// DecideJev maps TypeSafe answers onto approve/reject using code-owned policy.
// 破坏性判定与自定义运营策略优先于授权范围判定。
// Uncertain cases follow the product default: approve, unless a custom policy Choice rejects with high confidence.
func DecideJev(result *typesafe.Result) (decision, comment string) {
	if result == nil {
		return "reject", "audit agent: TypeSafe 无有效响应，保守拒绝"
	}
	availability := result.Noul(jevQAvailability)
	dataLoss := result.Noul(jevQDataLoss)
	credentials := result.Noul(jevQCredentials)
	configTamper := result.Noul(jevQConfig)
	scopedAction := result.Noul(jevQScopedAction)
	policyNoul := result.Noul(jevQOperatorPolicy)
	choice, choiceConf := result.Choice(jevQDecision)
	_, hasOperatorPolicy := result.Answers[jevQOperatorPolicy]

	type hit struct {
		id    string
		label string
		noul  float64
	}
	hits := []hit{
		{jevQAvailability, "破坏业务可用性", availability},
		{jevQDataLoss, "不可逆数据破坏", dataLoss},
		{jevQCredentials, "账号权限篡改", credentials},
		{jevQConfig, "改系统配置", configTamper},
		{jevQOperatorPolicy, "组织审批策略", policyNoul},
	}
	var fired []string
	maxReject := 0.0
	topLabel := ""
	for _, h := range hits {
		if h.noul > maxReject {
			maxReject = h.noul
			topLabel = h.label
		}
		if h.noul >= jevRejectThreshold {
			fired = append(fired, fmt.Sprintf("%s=%.2f", h.label, h.noul))
		}
	}

	decision = "approve"
	reason := "未命中破坏性规则，默认放行"
	if maxReject >= jevRejectThreshold {
		decision = "reject"
		reason = "命中拒绝规则：" + strings.Join(fired, "；")
	} else if strings.EqualFold(choice, "reject") && choiceConf >= 0.85 && (hasOperatorPolicy || (maxReject < 0.35 && scopedAction < 0.5)) {
		decision = "reject"
		if hasOperatorPolicy {
			reason = fmt.Sprintf("Jev 按组织策略拒绝（choice=%.2f，策略分=%.2f）", choiceConf, policyNoul)
		} else {
			reason = fmt.Sprintf("Jev 高置信拒绝（choice=%.2f，最高破坏分=%.2f）", choiceConf, maxReject)
		}
	}

	if decision == "approve" && topLabel != "" {
		reason = fmt.Sprintf("%s；最高破坏分=%s %.2f；授权操作分=%.2f", reason, topLabel, maxReject, scopedAction)
	}

	comment = fmt.Sprintf("audit agent: %s；choice=%s(%.2f)", reason, choice, choiceConf)
	return decision, comment
}
