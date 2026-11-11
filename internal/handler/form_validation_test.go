package handler

import (
	"testing"

	"go.uber.org/zap"
)

func TestBatchConcurrencyEditRejectsOutOfRangeWithoutMutation(t *testing.T) {
	m := NewBatchTaskManager(zap.NewNop())
	q, err := m.CreateBatchQueue("original", "", "eino_single", "manual", "", nil, 3, []string{"hello"})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{-1, 0, 9, 99} {
		if err := m.UpdateQueueMetadata(q.ID, "changed", "", "eino_single", &n); err == nil {
			t.Fatalf("accepted %d", n)
		}
		saved, _ := m.GetBatchQueue(q.ID)
		if saved.Concurrency != 3 || saved.Title != "original" {
			t.Fatalf("mutated queue: %#v", saved)
		}
	}
	for _, n := range []int{1, 8} {
		if err := m.UpdateQueueMetadata(q.ID, "original", "", "eino_single", &n); err != nil {
			t.Fatal(err)
		}
		saved, _ := m.GetBatchQueue(q.ID)
		if saved.Concurrency != n {
			t.Fatalf("saved %d, want %d", saved.Concurrency, n)
		}
	}
}
