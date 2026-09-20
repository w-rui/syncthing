// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package protocol

import (
	"context"
	"testing"
	"time"
)

func TestDomuneIndexDrainsTransport(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	c := &rawConnection{outbox: make(chan asyncMessage), closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- c.Index(context.Background(), &Index{Folder: "test"}) }()
	message := <-c.outbox
	select {
	case <-done:
		t.Fatal("index lease ended while wire message remained pending")
	case <-time.After(20 * time.Millisecond):
	}
	if message.done == nil {
		t.Fatal("transport completion not requested")
	}
	close(message.done)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
