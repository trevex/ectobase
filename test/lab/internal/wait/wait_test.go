package wait

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWaitForImmediate(t *testing.T) {
	err := WaitFor(context.Background(), 20*time.Millisecond, 5*time.Millisecond, func() (bool, error) {
		return true, nil
	})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestWaitForTimeout(t *testing.T) {
	sentinel := errors.New("still not ready")
	err := WaitFor(context.Background(), 20*time.Millisecond, 5*time.Millisecond, func() (bool, error) {
		return false, sentinel
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected error wrapping sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout message, got %q", err.Error())
	}
}
