// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/syncthing/syncthing/internal/db/sqlite"
	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/domuneacl"
	"github.com/syncthing/syncthing/lib/domunerules"
	"github.com/syncthing/syncthing/lib/ignore"
	"github.com/syncthing/syncthing/lib/protocol"
)

func TestDomuneACLBlocksDirectRequestAndReadonlyIndex(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	rawRules, _ := json.Marshal(map[string]any{"version": "domune-sync-rules/v1", "root": root, "logicalRoot": "", "generation": "one", "ancestors": []any{}, "controls": map[string]any{".gitignore": nil, ".syncignore": ""}})
	if err := domunerules.Apply(root, rawRules); err != nil {
		t.Fatal(err)
	}
	cfg := config.FolderConfiguration{ID: "probe", Path: root, FilesystemType: config.FilesystemTypeBasic, Devices: []config.FolderDeviceConfiguration{{DeviceID: device1}}}
	matcher := ignore.New(cfg.Filesystem())
	if err := matcher.Load(".gitignore"); err != nil {
		t.Fatal(err)
	}
	m := &model{folderCfgs: map[string]config.FolderConfiguration{"probe": cfg}, folderIgnores: map[string]*ignore.Matcher{"probe": matcher}}
	secret := filepath.Join(root, "private", "secret")
	if err := os.MkdirAll(filepath.Dir(secret), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	request := &protocol.Request{Folder: "probe", Name: "private/secret", Size: 6}
	if response, err := m.Request(device1Conn, request); err == nil || response != nil {
		t.Fatal("missing ACL served a direct block request")
	}
	rawACL, _ := json.Marshal(map[string]any{"version": "domune-sync-acl/v1", "root": root, "revision": "readonly", "devices": []any{map[string]any{"deviceID": device1.String(), "paths": []any{map[string]any{"path": "shared", "read": true, "write": false}}}}})
	if err := domuneacl.Apply(root, rawACL); err != nil {
		t.Fatal(err)
	}
	if response, err := m.Request(device1Conn, request); err == nil || response != nil {
		t.Fatal("unauthorized direct block request succeeded")
	}
	handler := &indexHandler{conn: device1Conn, folderRoot: root}
	for _, file := range []protocol.FileInfo{{Name: "shared/new"}, {Name: "shared/existing", Deleted: true}, {Name: "private/secret"}} {
		if err := handler.receive([]protocol.FileInfo{file}, true, "index update", 0, 1); err == nil {
			t.Errorf("readonly or out-of-path index accepted: %+v", file)
		}
	}
}

func TestDomuneReadonlyEchoRequiresAuthoritativeVersionAndContent(t *testing.T) {
	database, err := sqlite.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	version := protocol.Vector{}.Update(device1.Short())
	local := protocol.FileInfo{Name: "shared/file", Type: protocol.FileInfoTypeFile, Version: version, Sequence: 1, Size: 4, ModifiedS: 1234}
	if err := database.Update("probe", protocol.LocalDeviceID, []protocol.FileInfo{local}); err != nil {
		t.Fatal(err)
	}
	handler := &indexHandler{sdb: database, folder: "probe"}
	if !handler.readonlyEcho(local) {
		t.Fatal("identical read-only echo rejected")
	}
	changed := local
	changed.Version = version.Update(device2.Short())
	if handler.readonlyEcho(changed) {
		t.Fatal("new version accepted as read-only echo")
	}
	changed = local
	changed.Size++
	if handler.readonlyEcho(changed) {
		t.Fatal("changed content accepted as read-only echo")
	}
	changed = local
	changed.Deleted = true
	if handler.readonlyEcho(changed) {
		t.Fatal("malicious deletion of live file accepted")
	}
	tombstone := local
	tombstone.Deleted = true
	tombstone.Size = 0
	tombstone.Sequence = 2
	if err := database.Update("probe", protocol.LocalDeviceID, []protocol.FileInfo{tombstone}); err != nil {
		t.Fatal(err)
	}
	if !handler.readonlyEcho(tombstone) {
		t.Fatal("identical tombstone echo rejected")
	}
}
