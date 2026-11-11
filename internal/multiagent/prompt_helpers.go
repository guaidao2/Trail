package multiagent

import "strings"

// appendSystemPromptBlock 把调用方提供的附加系统提示拼到主指令后面。
// 项目层移除后，这里只保留最基础的拼接语义。
func appendSystemPromptBlock(instruction, extra string) string {
	instruction = strings.TrimSpace(instruction)
	extra = strings.TrimSpace(extra)
	if extra == "" {
		return instruction
	}
	return instruction + "\n\n" + extra
}

// appendVisionImageAnalysisIfReady 在视觉分析可用时补一段使用说明。
func appendVisionImageAnalysisIfReady(instruction string, ready bool) string {
	if !ready {
		return instruction
	}
	return instruction + "\n\n视觉分析已启用：可对截图、验证码与界面做分析，对话中只保留文字摘要。"
}
