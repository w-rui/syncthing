// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package model

import (
	"context"
	"encoding/json"
	"iter"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/syncthing/syncthing/internal/db"
	"github.com/syncthing/syncthing/internal/db/sqlite"
	"github.com/syncthing/syncthing/lib/domuneacl"
	"github.com/syncthing/syncthing/lib/domunerules"
	"github.com/syncthing/syncthing/lib/events"
	"github.com/syncthing/syncthing/lib/protocol"
	"github.com/syncthing/syncthing/lib/protocol/mocks"
)

type invalidatingIndexDB struct {
	db.DB
	root string
	once sync.Once
}

func (d *invalidatingIndexDB) AllLocalFilesBySequence(folder string, device protocol.DeviceID, startSeq int64, limit int) (iter.Seq[protocol.FileInfo], func() error) {
	files, errorFn := d.DB.AllLocalFilesBySequence(folder, device, startSeq, limit)
	return func(yield func(protocol.FileInfo) bool) {
		files(func(file protocol.FileInfo) bool {
			d.once.Do(func() { domunerules.Invalidate(d.root) })
			return yield(file)
		})
	}, errorFn
}

func TestDomuneIndexSenderWaitsForFreshAuthorityOnSameConnection(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	database, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	file := protocol.FileInfo{Name: "shared/file", Type: protocol.FileInfoTypeFile, Version: protocol.Vector{}.Update(myID.Short()), Sequence: 1, Size: 4}
	if err := database.Update("probe", protocol.LocalDeviceID, []protocol.FileInfo{file}); err != nil {
		t.Fatal(err)
	}
	conn := &mocks.Connection{}
	conn.DeviceIDReturns(device1)
	conn.StringReturns("same connection")
	sent := make(chan []protocol.FileInfo, 1)
	conn.IndexCalls(func(_ context.Context, index *protocol.Index) error {
		sent <- index.Files
		return nil
	})
	conn.IndexUpdateCalls(func(_ context.Context, update *protocol.IndexUpdate) error {
		sent <- update.Files
		return nil
	})
	handler := &indexHandler{conn: conn, folderRoot: root, folder: "probe", sdb: database, cond: sync.NewCond(new(sync.Mutex)), evLogger: events.NoopLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(ctx) }()

	assertWaiting := func(stage string) {
		t.Helper()
		select {
		case files := <-sent:
			t.Fatalf("%s leaked index content before fresh authority: %+v", stage, files)
		case err := <-done:
			t.Fatalf("%s killed same-connection sender: %v", stage, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	assertWaiting("missing rules")
	rules, _ := json.Marshal(map[string]any{"version": "domune-sync-rules/v1", "root": root, "logicalRoot": "photos", "generation": "fresh", "ancestors": []any{map[string]any{"scope": "", "content": ""}}, "controls": map[string]any{".gitignore": nil, ".syncignore": ""}})
	if err := domunerules.Apply(root, rules); err != nil {
		t.Fatal(err)
	}
	assertWaiting("missing ACL")
	acl, _ := json.Marshal(map[string]any{"version": "domune-sync-acl/v1", "root": root, "instanceId": domuneacl.Readiness(root).InstanceID, "generation": 1, "revision": "fresh", "devices": []any{map[string]any{"deviceID": device1.String(), "paths": []any{map[string]any{"path": "shared", "read": true, "write": false}}}}})
	handler.pause()
	if err := domuneacl.Apply(root, acl); err != nil {
		t.Fatal(err)
	}
	assertWaiting("folder paused after authority confirmation")
	handler.resume(nil)
	select {
	case files := <-sent:
		if len(files) != 1 || files[0].Name != file.Name {
			t.Fatalf("fresh authority sent wrong index: %+v", files)
		}
	case err := <-done:
		t.Fatalf("sender exited after fresh authority: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("fresh authority did not resume same-connection index")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled index sender leaked")
	}
}

func TestDomuneIndexSenderCancelsWhilePermanentlyUnauthorized(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	conn := &mocks.Connection{}
	conn.DeviceIDReturns(device1)
	conn.StringReturns("unconfirmed connection")
	var sent bool
	conn.IndexCalls(func(context.Context, *protocol.Index) error { sent = true; return nil })
	handler := &indexHandler{conn: conn, folderRoot: t.TempDir(), folder: "probe", cond: sync.NewCond(new(sync.Mutex)), evLogger: events.NoopLogger}
	done := make(chan error, 1)
	go func() { done <- handler.Serve(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("unconfirmed sender exited instead of waiting: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unconfirmed sender leaked after disconnect")
	}
	if sent {
		t.Fatal("unconfirmed connection received index")
	}
}

func TestDomuneIndexSenderRetriesUnsentReadAheadAfterInvalidation(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	rules, _ := json.Marshal(map[string]any{"version": "domune-sync-rules/v1", "root": root, "logicalRoot": "photos", "generation": "fresh", "ancestors": []any{map[string]any{"scope": "", "content": ""}}, "controls": map[string]any{".gitignore": nil, ".syncignore": ""}})
	if err := domunerules.Apply(root, rules); err != nil {
		t.Fatal(err)
	}
	acl, _ := json.Marshal(map[string]any{"version": "domune-sync-acl/v1", "root": root, "instanceId": domuneacl.Readiness(root).InstanceID, "generation": 1, "revision": "fresh", "devices": []any{map[string]any{"deviceID": device1.String(), "paths": []any{map[string]any{"path": "shared", "read": true, "write": false}}}}})
	if err := domuneacl.Apply(root, acl); err != nil {
		t.Fatal(err)
	}
	database, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	file := protocol.FileInfo{Name: "shared/unread", Type: protocol.FileInfoTypeFile, Version: protocol.Vector{}.Update(myID.Short()), Sequence: 1, Size: 4}
	if err := database.Update("probe", protocol.LocalDeviceID, []protocol.FileInfo{file}); err != nil {
		t.Fatal(err)
	}
	conn := &mocks.Connection{}
	conn.DeviceIDReturns(device1)
	conn.StringReturns("same connection")
	sent := make(chan []protocol.FileInfo, 1)
	conn.IndexCalls(func(_ context.Context, index *protocol.Index) error {
		sent <- index.Files
		return nil
	})
	handler := &indexHandler{conn: conn, folderRoot: root, folder: "probe", sdb: &invalidatingIndexDB{DB: database, root: root}, cond: sync.NewCond(new(sync.Mutex)), evLogger: events.NoopLogger}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(ctx) }()
	select {
	case files := <-sent:
		t.Fatalf("stale authority leaked unsent index: %+v", files)
	case err := <-done:
		t.Fatalf("read-ahead invalidation killed sender: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := domunerules.Apply(root, rules); err != nil {
		t.Fatal(err)
	}
	select {
	case files := <-sent:
		if len(files) != 1 || files[0].Name != file.Name {
			t.Fatalf("read-ahead recovery lost file: %+v", files)
		}
	case err := <-done:
		t.Fatalf("read-ahead recovery failed: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("read-ahead recovery did not send file")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sender did not stop after cancellation")
	}
}

func TestDomuneIndexSenderDoesNotWaitThroughInvalidRuleControl(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	control := filepath.Join(root, ".syncignore")
	if err := os.WriteFile(control, nil, 0600); err != nil {
		t.Fatal(err)
	}
	rules, _ := json.Marshal(map[string]any{"version": "domune-sync-rules/v1", "root": root, "logicalRoot": "photos", "generation": "fresh", "ancestors": []any{map[string]any{"scope": "", "content": ""}}, "controls": map[string]any{".gitignore": nil, ".syncignore": ""}})
	if err := domunerules.Apply(root, rules); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(control, []byte("unexpected\n"), 0600); err != nil {
		t.Fatal(err)
	}
	conn := &mocks.Connection{}
	conn.DeviceIDReturns(device1)
	conn.StringReturns("invalid controls")
	handler := &indexHandler{conn: conn, folderRoot: root, folder: "probe", cond: sync.NewCond(new(sync.Mutex)), evLogger: events.NoopLogger}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Serve(ctx); err == nil || err == context.DeadlineExceeded {
		t.Fatalf("invalid rule control was treated as authority wait: %v", err)
	}
}
