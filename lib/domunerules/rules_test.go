// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package domunerules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func contextBytes(root, generation string, controls map[string]any) []byte {
	data, _ := json.Marshal(map[string]any{"version": "domune-sync-rules/v1", "root": root, "logicalRoot": "photos", "generation": generation, "ancestors": []any{map[string]any{"scope": "", "content": "build/\n"}}, "controls": controls})
	return data
}
func TestReadinessMissingAndRecursiveControls(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	if _, err := Acquire(root); err == nil {
		t.Fatal("missing context accepted")
	}
	controls := map[string]any{".gitignore": nil, ".syncignore": ""}
	if err := Apply(root, contextBytes(root, "one", controls)); err == nil {
		t.Fatal("missing manual local rule treated as empty")
	}
	os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600)
	if err := Apply(root, contextBytes(root, "one", controls)); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
	os.Mkdir(filepath.Join(root, "nested"), 0700)
	os.WriteFile(filepath.Join(root, "nested/.gitignore"), []byte("build/\n"), 0600)
	if _, err := Acquire(root); err == nil {
		t.Fatal("unacknowledged nested control accepted")
	}
	controls["nested/.gitignore"] = "build/\n"
	if err := Apply(root, contextBytes(root, "two", controls)); err != nil {
		t.Fatal(err)
	}
	lease, err = Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "nested/.gitignore"), []byte("photos/\n"), 0600)
	if err := lease.Check(); err == nil {
		t.Fatal("final boundary accepted changed control")
	}
	lease.Close()
}
func TestApplyDrainsAndBindsGeneration(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600)
	controls := map[string]any{".gitignore": nil, ".syncignore": ""}
	if err := Apply(root, contextBytes(root, "one", controls)); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Apply(root, contextBytes(root, "two", controls)) }()
	select {
	case <-done:
		t.Fatal("apply did not drain active lease")
	case <-time.After(30 * time.Millisecond):
	}
	lease.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	data := contextBytes(root, "two", controls)
	var value map[string]any
	json.Unmarshal(data, &value)
	value["logicalRoot"] = "other"
	data, _ = json.Marshal(value)
	before, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	identity := before.Generation()
	before.Close()
	if err := Apply(root, data); err != nil {
		t.Fatal(err)
	}
	after, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if after.Generation() == identity {
		t.Fatal("changed context reused checked identity")
	}
}

func TestIdentityBindsABAAndFirstPostAfterRestart(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	controls := map[string]any{".gitignore": nil, ".syncignore": ""}
	apply := func(label, local string) string {
		t.Helper()
		controls[".syncignore"] = local
		os.WriteFile(filepath.Join(root, ".syncignore"), []byte(local), 0600)
		if err := Apply(root, contextBytes(root, label, controls)); err != nil {
			t.Fatal(err)
		}
		lease, err := Acquire(root)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		return lease.Generation()
	}
	original := apply("A", "")
	apply("B", "")
	changed := apply("A", "secret\n")
	if original == changed {
		t.Fatal("ABA reused checked identity for changed rules")
	}
	gates.Delete(os.Getenv("DOMUNE_RULES_DIR") + "\x00" + root)
	restarted := apply("A", "other\n")
	if changed == restarted {
		t.Fatal("first POST after restart reused checked identity")
	}
}
func TestRestartRequiresFreshAuthority(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600)
	if err := Apply(root, contextBytes(root, "A", map[string]any{".gitignore": nil, ".syncignore": ""})); err != nil {
		t.Fatal(err)
	}
	gates.Delete(os.Getenv("DOMUNE_RULES_DIR") + "\x00" + root)
	if lease, err := Acquire(root); err == nil {
		lease.Close()
		t.Fatal("persisted ancestors were trusted after restart")
	}
}

func TestDisconnectRevokesOutstandingLease(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600)
	data := contextBytes(root, "A", map[string]any{".gitignore": nil, ".syncignore": ""})
	if err := Apply(root, data); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	Invalidate(root)
	if err := lease.Check(); err == nil {
		t.Fatal("disconnect left active lease authorized")
	}
	lease.Close()
	if lease, err := Acquire(root); err == nil {
		lease.Close()
		t.Fatal("disconnect left new work authorized")
	}
	if err := Apply(root, data); err != nil {
		t.Fatal(err)
	}
	lease, err = Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
}

func TestRootLocalReconnectHasNoExternalAuthorityDependency(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".syncignore"), nil, 0600)
	var value map[string]any
	json.Unmarshal(contextBytes(root, "A", map[string]any{".gitignore": nil, ".syncignore": ""}), &value)
	value["logicalRoot"] = ""
	value["ancestors"] = []any{}
	raw, _ := json.Marshal(value)
	if err := Apply(root, raw); err != nil {
		t.Fatal(err)
	}
	Invalidate(root)
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
	os.WriteFile(filepath.Join(root, ".gitignore"), []byte("new-rule\n"), 0600)
	if lease, err := Acquire(root); err == nil {
		lease.Close()
		t.Fatal("root-local exception skipped local control validation")
	}
}
