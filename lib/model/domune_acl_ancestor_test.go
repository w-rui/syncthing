// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package model

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/syncthing/syncthing/internal/db/sqlite"
	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/domuneacl"
	"github.com/syncthing/syncthing/lib/protocol"
)

func TestDomuneACLRejectsParentReplacementOverRestrictedDescendant(t *testing.T) {
	for _, restriction := range []struct {
		name  string
		read  bool
		write bool
	}{
		{name: "none"},
		{name: "readonly", read: true},
	} {
		t.Run(restriction.name, func(t *testing.T) {
			t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
			root := t.TempDir()
			raw, _ := json.Marshal(map[string]any{
				"version": "domune-sync-acl/v1", "root": root,
				"instanceId": domuneacl.Readiness(root).InstanceID,
				"generation": 1, "revision": "ancestor-test",
				"devices": []any{map[string]any{
					"deviceID": device1.String(), "paths": []any{
						map[string]any{"path": "", "read": true, "write": true},
						map[string]any{"path": "shared/private", "read": restriction.read, "write": restriction.write},
					},
				}},
			})
			if err := domuneacl.Apply(root, raw); err != nil {
				t.Fatal(err)
			}
			handler := &indexHandler{conn: device1Conn, folderRoot: root, paused: true, cond: sync.NewCond(new(sync.Mutex))}
			for _, file := range []protocol.FileInfo{
				{Name: "shared", Type: protocol.FileInfoTypeDirectory, Deleted: true, Sequence: 1},
				{Name: "shared", Type: protocol.FileInfoTypeFile, Sequence: 1},
				{Name: "shared", Type: protocol.FileInfoTypeSymlink, Sequence: 1, SymlinkTarget: []byte("elsewhere")},
			} {
				if err := handler.receive([]protocol.FileInfo{file}, true, "index update", 0, 1); err == nil || !strings.Contains(err.Error(), "ACL denied") {
					t.Errorf("parent %s replacement was not rejected by ACL: %v", file.Type, err)
				}
			}
		})
	}
}

func TestDomuneACLRetainedParentTombstoneDeniedAfterNarrowerRestriction(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	database, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tombstone := protocol.FileInfo{Name: "shared", Type: protocol.FileInfoTypeDirectory, Deleted: true, Sequence: 1, Version: protocol.Vector{}.Update(device1.Short())}
	if err := database.Update("probe", device1, []protocol.FileInfo{tombstone}); err != nil {
		t.Fatal(err)
	}
	cfg := config.FolderConfiguration{ID: "probe", Path: root}
	f := &sendReceiveFolder{folder: &folder{FolderConfiguration: cfg, stateTracker: stateTracker{folderID: "probe"}, model: &model{sdb: database}}}
	apply := func(generation int, restricted bool) {
		t.Helper()
		paths := []any{map[string]any{"path": "", "read": true, "write": true}}
		if restricted {
			paths = append(paths, map[string]any{"path": "shared/private", "read": false, "write": false})
		}
		raw, _ := json.Marshal(map[string]any{"version": "domune-sync-acl/v1", "root": root, "instanceId": domuneacl.Readiness(root).InstanceID, "generation": generation, "revision": string(rune('0' + generation)), "devices": []any{map[string]any{"deviceID": device1.String(), "paths": paths}}})
		if err := domuneacl.Apply(root, raw); err != nil {
			t.Fatal(err)
		}
	}
	apply(1, false)
	lease, err := f.incomingACL(tombstone)
	if err != nil {
		t.Fatalf("unrestricted source rejected: %v", err)
	}
	lease.Close()
	apply(2, true)
	if lease, err := f.incomingACL(tombstone); err == nil {
		lease.Close()
		t.Fatal("retained parent tombstone remained executable after narrower restriction")
	}
}
