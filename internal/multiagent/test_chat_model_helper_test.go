package multiagent

import (
	"context"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// capturingClassicChatModel 是测试用的经典 ChatModel 桩：按预设返回助手消息并记录调用次数。
// 原先定义在已删除的 eino_summarize_test.go，多个多代理测试仍在使用，这里保留共享实现。
type capturingClassicChatModel struct {
	output  *schema.Message
	outputs []*schema.Message
	calls   int
}

func (m *capturingClassicChatModel) Generate(_ context.Context, _ []*schema.Message, _ ...model.Option) (*schema.Message, error) {
	m.calls++
	if len(m.outputs) > 0 {
		idx := m.calls - 1
		if idx >= len(m.outputs) {
			idx = len(m.outputs) - 1
		}
		return m.outputs[idx], nil
	}
	if m.output != nil {
		return m.output, nil
	}
	return schema.AssistantMessage("classic answer", nil), nil
}

func (m *capturingClassicChatModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	msg, err := m.Generate(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	return schema.StreamReaderFromArray([]*schema.Message{msg}), nil
}
