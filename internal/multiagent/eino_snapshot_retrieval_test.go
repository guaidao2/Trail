package multiagent

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trail/internal/config"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

func TestFailedTranscriptWriteDoesNotLeaveFrameworkAliasHint(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%v", native), func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Database.Path = filepath.Join(t.TempDir(), "runtime.db")
			cfg.OpenAI.Model = "gpt-4o"
			cfg.OpenAI.MaxTotalTokens = 5000
			emit := false
			mwCfg := &config.MultiAgentEinoMiddlewareConfig{SummarizationEmitInternalEvents: &emit, SummarizationOutputReserveTokens: 1024}
			ctx := context.Background()
			base := filepath.Join(filepath.Dir(cfg.Database.Path), "conversation_artifacts", "failure", "summarization")
			if err := os.MkdirAll(base, 0o700); err != nil {
				t.Fatal(err)
			}
			// Make snapshot creation fail while the middleware can still create its base directory.
			if err := os.WriteFile(filepath.Join(base, "snapshots"), []byte("blocked"), 0o600); err != nil {
				t.Fatal(err)
			}
			original := []adk.Message{schema.SystemMessage("system"), schema.UserMessage(strings.Repeat("history ", 20000)), schema.UserMessage("continue")}
			const summary = "<summary>usable continuation</summary>"
			var after []adk.Message
			if native {
				mw, err := newEinoAgenticSummarizationMiddleware(ctx, &capturingAgenticChatModel{output: agenticAssistantTextMessage(summary)}, cfg, mwCfg, "failure", nil, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				_, state, err := mw.BeforeModelRewriteState(ctx, &adk.TypedChatModelAgentState[*schema.AgenticMessage]{Messages: EinoMessagesToAgentic(original)}, nil)
				if err != nil {
					t.Fatal(err)
				}
				after = AgenticMessagesToEino(state.Messages)
			} else {
				mw, err := newEinoSummarizationMiddleware(ctx, &capturingClassicChatModel{output: &schema.Message{Role: schema.Assistant, Content: summary, ResponseMeta: &schema.ResponseMeta{FinishReason: "stop"}}}, cfg, mwCfg, "failure", nil, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				_, state, err := mw.BeforeModelRewriteState(ctx, &adk.ChatModelAgentState{Messages: original}, nil)
				if err != nil {
					t.Fatal(err)
				}
				after = state.Messages
			}
			text := joinClassicMessageContent(after)
			if !strings.Contains(text, "usable continuation") || strings.Contains(text, "transcript.txt") || strings.Contains(text, summarizationSnapshotHeading) {
				t.Fatalf("failed snapshot has a misleading retrieval hint: %s", text)
			}
		})
	}
}

func TestConcurrentSnapshotWritesRemainCompleteAndDeduplicated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transcript.txt")
	var wg sync.WaitGroup
	errors := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msgs := []adk.Message{schema.UserMessage(fmt.Sprintf("Cookie: fixture-%d", i%2))}
			snapshot, err := writeSummarizationTranscriptSnapshot(path, msgs)
			if err == nil {
				var body []byte
				body, err = os.ReadFile(snapshot)
				if err == nil && !bytes.Equal(body, []byte(formatSummarizationTranscript(msgs))) {
					err = fmt.Errorf("partial or mismatched snapshot: %s", snapshot)
				}
			}
			errors <- err
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "snapshots", "*.txt"))
	indexes, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "snapshots", "*.index.md"))
	if len(files) != 2 || len(indexes) != 0 {
		t.Fatalf("concurrent retries not deduplicated: %v %v", files, indexes)
	}
}

func TestLegacyIndexArtifactDoesNotBlockSnapshotWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transcript.txt")
	msgs := []adk.Message{schema.UserMessage("Cookie: fixture")}
	snapshot, err := writeSummarizationTranscriptSnapshot(path, msgs)
	if err != nil {
		t.Fatal(err)
	}
	// Old index artifacts are ignored rather than edited or depended on.
	if err := os.Mkdir(snapshot+".index.md", 0o700); err != nil {
		t.Fatal(err)
	}
	again, err := writeSummarizationTranscriptSnapshot(path, msgs)
	if err != nil || again != snapshot {
		t.Fatalf("legacy index affected snapshot: %s %v", again, err)
	}
}

func TestSnapshotNamesContainShortMD5AndStableTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transcript.txt")
	msgs := []adk.Message{schema.UserMessage("first evidence")}
	snapshot, err := writeSummarizationTranscriptSnapshot(path, msgs)
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("%x", md5.Sum([]byte(formatSummarizationTranscript(msgs))))[:5]
	name := filepath.Base(snapshot)
	stamp := strings.TrimSuffix(strings.TrimPrefix(name, "transcript-"+prefix+"-"), ".txt")
	if _, err := time.Parse(transcriptSnapshotTimeLayout, stamp); err != nil {
		t.Fatalf("invalid timestamp filename %s: %v", name, err)
	}
	before, _ := os.Stat(snapshot)
	again, err := writeSummarizationTranscriptSnapshot(path, msgs)
	after, _ := os.Stat(snapshot)
	if err != nil || again != snapshot || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("retry changed snapshot time/path: %v", err)
	}
}

func TestShortDigestOrTimestampCollisionDoesNotOverwriteEvidence(t *testing.T) {
	dir := t.TempDir()
	body := []byte("current evidence")
	prefix := fmt.Sprintf("%x", md5.Sum(body))[:5]
	stamp := time.Date(2026, 10, 12, 1, 2, 3, 4, time.FixedZone("CST", 8*3600))
	collision := filepath.Join(dir, "transcript-"+prefix+"-"+stamp.Format(transcriptSnapshotTimeLayout)+".txt")
	if err := os.WriteFile(collision, []byte("different evidence with same short label"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := findOrCreateTranscriptSnapshot(dir, body, stamp)
	if err != nil || snapshot == collision {
		t.Fatalf("collision overwrote old path: %s %v", snapshot, err)
	}
	old, _ := os.ReadFile(collision)
	if string(old) != "different evidence with same short label" {
		t.Fatal("old evidence overwritten")
	}
	again, err := findOrCreateTranscriptSnapshot(dir, body, stamp.Add(time.Second))
	if err != nil || again != snapshot {
		t.Fatalf("retry did not verify full body: %s %v", again, err)
	}
}

func TestLegacySHA256SnapshotRemainsReachableAndDeduplicated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transcript.txt")
	msgs := []adk.Message{schema.UserMessage("legacy evidence")}
	body := []byte(formatSummarizationTranscript(msgs))
	dir := filepath.Join(filepath.Dir(path), "snapshots")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, fmt.Sprintf("transcript-%x.txt", sha256.Sum256(body)))
	if err := os.WriteFile(legacy, body, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := writeSummarizationTranscriptSnapshot(path, msgs)
	if err != nil || snapshot != legacy {
		t.Fatalf("legacy snapshot not reused: %s %v", snapshot, err)
	}
}

func TestFallbackSnapshotDirectoryIsSeparatedByConversation(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	t.Setenv("TMP", root)
	t.Setenv("TEMP", root)
	for _, native := range []bool{false, true} {
		for _, conv := range []string{"fallback-a", "fallback-b"} {
			cfg := &config.Config{}
			cfg.OpenAI.Model = "gpt-4o"
			cfg.OpenAI.MaxTotalTokens = 5000
			emit := false
			mwCfg := &config.MultiAgentEinoMiddlewareConfig{SummarizationEmitInternalEvents: &emit, SummarizationOutputReserveTokens: 1024}
			original := []adk.Message{schema.SystemMessage("system"), schema.UserMessage(strings.Repeat("old output ", 20000)), schema.UserMessage("continue authorized target")}
			const summary = "<summary>kept progress</summary>"
			ctx := context.Background()
			var after []adk.Message
			if native {
				mw, err := newEinoAgenticSummarizationMiddleware(ctx, &capturingAgenticChatModel{output: agenticAssistantTextMessage(summary)}, cfg, mwCfg, conv, nil, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				_, state, err := mw.BeforeModelRewriteState(ctx, &adk.TypedChatModelAgentState[*schema.AgenticMessage]{Messages: EinoMessagesToAgentic(original)}, nil)
				if err != nil {
					t.Fatal(err)
				}
				after = AgenticMessagesToEino(state.Messages)
			} else {
				model := &capturingClassicChatModel{output: &schema.Message{Role: schema.Assistant, Content: summary, ResponseMeta: &schema.ResponseMeta{FinishReason: "stop"}}}
				mw, err := newEinoSummarizationMiddleware(ctx, model, cfg, mwCfg, conv, nil, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				_, state, err := mw.BeforeModelRewriteState(ctx, &adk.ChatModelAgentState{Messages: original}, nil)
				if err != nil {
					t.Fatal(err)
				}
				after = state.Messages
			}
			want := filepath.Join(os.TempDir(), "cyberstrike-summarization", conv, "summarization", "snapshots")
			if !strings.Contains(joinClassicMessageContent(after), want) {
				t.Fatalf("missing conversation in fallback path: %s", joinClassicMessageContent(after))
			}
			files, err := filepath.Glob(filepath.Join(want, "*.txt"))
			if err != nil || len(files) != 1 {
				t.Fatalf("fallback snapshots not scoped/deduplicated: %v %v", files, err)
			}
		}
	}
}

