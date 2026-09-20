// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

package ignore

import (
	"encoding/json"
	"github.com/syncthing/syncthing/lib/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomuneGitOracle(t *testing.T) {
	t.Setenv("DOMUNE_GITIGNORE", "1")
	var fixture struct {
		Rules       map[string]string
		Files       map[string]bool
		Directories map[string]bool
	}
	name := os.Getenv("DOMUNE_GITIGNORE_FIXTURES")
	if name == "" {
		name = "../../../../../../tests/fixtures/gitignore/cases.json"
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range fixture.Rules {
		write(name, value)
	}
	for name := range fixture.Files {
		write(name, "payload")
	}
	for name := range fixture.Directories {
		if err := os.MkdirAll(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) error {
		cmd := exec.Command("git", append([]string{"-C", root, "-c", "core.ignorecase=false", "-c", "core.excludesFile=/dev/null"}, args...)...)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "GIT_") {
				cmd.Env = append(cmd.Env, value)
			}
		}
		cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
		return cmd.Run()
	}
	if err := git("init", "--quiet"); err != nil {
		t.Fatal(err)
	}
	m := New(fs.NewFilesystem(fs.FilesystemTypeBasic, root))
	if err := m.Load(".stignore"); err != nil && !fs.IsNotExist(err) {
		t.Fatal(err)
	}
	check := func(name string, want bool) {
		t.Helper()
		oracle := git("check-ignore", "--quiet", "--no-index", "--", name)
		ignored := oracle == nil
		if oracle != nil {
			if exit, ok := oracle.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				t.Fatal(oracle)
			}
		}
		if ignored != want {
			t.Fatalf("invalid fixture %q Git=%v want=%v", name, ignored, want)
		}
		if got := m.Match(name).IsIgnored(); got != ignored {
			t.Errorf("%q matcher=%v Git=%v", name, got, ignored)
		}
	}
	for name, want := range fixture.Files {
		check(name, want)
	}
	for name, want := range fixture.Directories {
		check(name, want)
	}
}

func TestDomuneGitLocalLayerAndDeletion(t *testing.T) {
	t.Setenv("DOMUNE_GITIGNORE", "1")
	root := t.TempDir()
	f := fs.NewFilesystem(fs.FilesystemTypeBasic, root)
	put := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	put(".gitignore", "common.txt\n")
	put(".syncignore", "!common.txt\nlocal.txt\n")
	put(".stignore", "ordinary.txt\n")
	put("common.txt", "preserve")
	m := New(f)
	load := func() {
		t.Helper()
		if err := m.Load(".stignore"); err != nil {
			t.Fatal(err)
		}
	}
	load()
	for _, name := range []string{"common.txt", "local.txt", ".syncignore"} {
		if !m.Match(name).IsIgnored() {
			t.Errorf("%s not excluded", name)
		}
	}
	if m.Match("ordinary.txt").IsIgnored() {
		t.Error("native stignore must not drive Git mode")
	}
	hash := m.Hash()
	put(".syncignore", "!common.txt\n")
	load()
	if m.Hash() == hash || m.Match("local.txt").IsIgnored() {
		t.Error("local update did not invalidate")
	}
	hash = m.Hash()
	if err := os.Remove(filepath.Join(root, ".gitignore")); err != nil {
		t.Fatal(err)
	}
	load()
	if m.Hash() == hash || m.Match("common.txt").IsIgnored() {
		t.Error("deletion did not invalidate")
	}
	if data, err := os.ReadFile(filepath.Join(root, "common.txt")); err != nil || string(data) != "preserve" {
		t.Fatal("rule change removed content", err)
	}
}

func TestDomuneGitAncestorScope(t *testing.T) {
	for _, binding := range []string{"first", "unrelated-host"} {
		t.Run(binding, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), binding)
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			m := New(fs.NewFilesystem(fs.FilesystemTypeBasic, root), WithGitContext("photos", []GitRule{{Scope: "", Content: "/photos/cache/\n"}}))
			if err := m.Load(".stignore"); err != nil {
				t.Fatal(err)
			}
			if !m.Match("cache/file").IsIgnored() || m.Match("ordinary").IsIgnored() {
				t.Fatal("logical scope differs across physical roots")
			}
			blocked := New(fs.NewFilesystem(fs.FilesystemTypeBasic, root), WithGitContext("photos/hidden", []GitRule{{Scope: "", Content: "photos/\n!photos/hidden/item\n"}}))
			if err := blocked.Load(".stignore"); err != nil {
				t.Fatal(err)
			}
			if !blocked.Match("item").IsIgnored() {
				t.Fatal("excluded logical ancestor incorrectly reopened")
			}
		})
	}
}

func TestDomuneGitControlReadFailurePreservesSnapshot(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, ".syncignore")
	if err := os.WriteFile(p, []byte("private\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := New(fs.NewFilesystem(fs.FilesystemTypeBasic, root), WithGitContext("", nil))
	if err := m.Load(".stignore"); err != nil {
		t.Fatal(err)
	}
	hash := m.Hash()
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(".stignore"); err == nil {
		t.Fatal("non-file control accepted")
	}
	if m.Hash() != hash || !m.Match("private").IsIgnored() {
		t.Fatal("failed load replaced good snapshot")
	}
	if m.WatchMatcher().Match(".syncignore").IsIgnored() {
		t.Fatal("local control is invisible to watcher")
	}
	if m.WatchMatcher().Match("private/.gitignore").IsIgnored() {
		t.Fatal("nested control is invisible to watcher")
	}
}

func TestDomuneGitNewNestedRulesAndDirectoryKinds(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	m := New(fs.NewFilesystem(fs.FilesystemTypeBasic, root), WithGitContext("", nil))
	if err := m.Load(".stignore"); err != nil {
		t.Fatal(err)
	}
	hash := m.Hash()
	control := filepath.Join(root, "nested/.gitignore")
	if err := os.WriteFile(control, []byte("cache/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(".stignore"); err != nil {
		t.Fatal(err)
	}
	if m.Hash() == hash || !m.MatchEntry("nested/cache", true).IsIgnored() || m.MatchEntry("nested/cache", false).IsIgnored() {
		t.Fatal("new nested scope or remote directory kind ignored")
	}
	if err := os.Remove(control); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(".stignore"); err != nil {
		t.Fatal(err)
	}
	if m.MatchEntry("nested/cache", true).IsIgnored() {
		t.Fatal("removed nested rule remains active")
	}
	outside := filepath.Join(t.TempDir(), "rule")
	if err := os.WriteFile(outside, []byte("*\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, control); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(".stignore"); err == nil {
		t.Fatal("control symlink read outside unit")
	}
}
