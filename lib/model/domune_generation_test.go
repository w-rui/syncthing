// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package model

import (
	"encoding/json"
	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/domunerules"
	"github.com/syncthing/syncthing/lib/fs"
	"github.com/syncthing/syncthing/lib/ignore"
	"github.com/syncthing/syncthing/lib/protocol"
	"os"
	"path/filepath"
	"testing"
)

func TestDomuneFinalWriteRejectsChangedControlsAndGeneration(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600)
	apply := func(generation, local string) {
		t.Helper()
		os.WriteFile(filepath.Join(root, ".syncignore"), []byte(local), 0600)
		data, _ := json.Marshal(map[string]any{"version": "domune-sync-rules/v1", "root": root, "logicalRoot": "", "generation": generation, "ancestors": []any{}, "controls": map[string]any{".gitignore": nil, ".syncignore": local}})
		if err := domunerules.Apply(root, data); err != nil {
			t.Fatal(err)
		}
	}
	apply("one", "")
	matcher := ignore.New(fs.NewFilesystem(fs.FilesystemTypeBasic, root))
	if err := matcher.Load(".gitignore"); err != nil {
		t.Fatal(err)
	}
	f := &sendReceiveFolder{folder: &folder{FolderConfiguration: config.FolderConfiguration{Path: root}, ignores: matcher}}
	os.WriteFile(filepath.Join(root, "payload"), []byte("original"), 0600)
	os.WriteFile(filepath.Join(root, ".syncthing.payload.tmp"), []byte("incoming"), 0600)
	finish := func() {
		t.Helper()
		if err := f.performFinish(protocol.FileInfo{Name: "payload"}, protocol.FileInfo{}, false, ".syncthing.payload.tmp", make(chan dbUpdateJob, 1), make(chan string, 1)); err == nil {
			t.Fatal("unsafe final write accepted")
		}
		data, _ := os.ReadFile(filepath.Join(root, "payload"))
		if string(data) != "original" {
			t.Fatal("existing content mutated")
		}
	}
	os.WriteFile(filepath.Join(root, ".syncignore"), []byte("payload\n"), 0600)
	finish()
	apply("two", "payload\n")
	finish() // old queued generation cannot write under new rules
}

func TestDomuneRetainedMatcherRejectsABA(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	apply := func(label, local string) {
		t.Helper()
		os.WriteFile(filepath.Join(root, ".syncignore"), []byte(local), 0600)
		raw, _ := json.Marshal(map[string]any{"version": "domune-sync-rules/v1", "root": root, "logicalRoot": "", "generation": label, "ancestors": []any{}, "controls": map[string]any{".gitignore": nil, ".syncignore": local}})
		if err := domunerules.Apply(root, raw); err != nil {
			t.Fatal(err)
		}
	}
	apply("A", "")
	matcher := ignore.New(fs.NewFilesystem(fs.FilesystemTypeBasic, root))
	if err := matcher.Load(".gitignore"); err != nil {
		t.Fatal(err)
	}
	apply("B", "")
	apply("A", "secret\n")
	if matcher.MatchEntry("secret", false).IsIgnored() {
		t.Fatal("retained matcher unexpectedly mutated")
	}
	if lease, err := domuneLease(root, matcher.Hash()); err == nil {
		lease.Close()
		t.Fatal("old matcher proof accepted ABA context")
	}
	if err := matcher.Load(".gitignore"); err != nil {
		t.Fatal(err)
	}
	if !matcher.MatchEntry("secret", false).IsIgnored() {
		t.Fatal("fresh matcher did not enforce new rules")
	}
	lease, err := domuneLease(root, matcher.Hash())
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
}
