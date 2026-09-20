// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDomuneProbeRejectsMissingReadiness(t *testing.T) {
	t.Setenv("DOMUNE_RULE_PROBE", filepath.Join(t.TempDir(), "missing.json"))
	if err := domuneProbeRulesReady(t.TempDir()); err == nil {
		t.Fatal("missing readiness accepted")
	}
}

func TestDomuneProbeRejectsStaleAndDistinguishesAbsence(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(t.TempDir(), "rules.json")
	t.Setenv("DOMUNE_RULE_PROBE", manifest)
	// SHA256 of empty file; absence is explicit and is not an empty file.
	content := `{"root":` + `"` + root + `","generation":"one","rules":{".stignore":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",".gitignore":"absent",".syncignore":"absent"}}`
	if err := os.WriteFile(manifest, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".stignore"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := domuneProbeRulesReady(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := domuneProbeRulesReady(root); err == nil {
		t.Fatal("unexpected rule file accepted")
	}
	if err := os.Remove(filepath.Join(root, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".stignore"), []byte("build\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := domuneProbeRulesReady(root); err == nil {
		t.Fatal("stale digest accepted")
	}
}
