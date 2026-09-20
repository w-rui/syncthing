// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

package ignore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"

	gitignore "github.com/denormal/go-gitignore"
	"github.com/syncthing/syncthing/lib/domunerules"
	"github.com/syncthing/syncthing/lib/fs"
	"github.com/syncthing/syncthing/lib/ignore/ignoreresult"
)

// GitRule is a supplied logical ancestor scope, never a host filesystem path.
// Runtime must bind these immutable bytes to its readiness generation (C2).
type GitRule struct {
	Scope   string
	Content string
}
type scopedGitRule struct {
	scope   string
	matcher gitignore.GitIgnore
}
type gitRules struct {
	common []scopedGitRule
	local  gitignore.GitIgnore
}

// WithGitContext supplies ancestor rules in broadest-to-nearest precedence order.
// logicalRoot is relative to the governed Domain, not to any host directory.
func WithGitContext(logicalRoot string, ancestors []GitRule) Option {
	return func(m *Matcher) {
		m.gitEnabled = true
		m.gitRoot = logicalRoot
		m.gitAncestors = append([]GitRule(nil), ancestors...)
	}
}

func validGitScope(s string) bool {
	return s == "" || (path.Clean(s) == s && !path.IsAbs(s) && s != ".." && !strings.HasPrefix(s, "../") && !strings.Contains(s, "\\"))
}
func underGitScope(name, scope string) bool { return scope == "" || strings.HasPrefix(name, scope+"/") }
func parseGit(data []byte) (gitignore.GitIgnore, error) {
	var failure error
	matcher := gitignore.New(bytes.NewReader(data), "", func(e gitignore.Error) bool {
		failure = e
		return false
	})
	return matcher, failure
}

// loadGit discovers nested controls separately from content filtering. It never
// follows a control symlink and installs a new snapshot only after full success.
func (m *Matcher) loadGit() error {
	if domunerules.Enabled() {
		return m.loadAcknowledgedGit()
	}
	m.mut.Lock()
	defer m.mut.Unlock()
	if !validGitScope(m.gitRoot) {
		return parseError(fmt.Errorf("invalid logical Git scope"))
	}
	next := &gitRules{}
	digest := sha256.New()
	add := func(scope string, data []byte) error {
		matcher, err := parseGit(data)
		if err != nil {
			return err
		}
		next.common = append(next.common, scopedGitRule{scope, matcher})
		fmt.Fprintf(digest, "common:%d:%s:%d:", len(scope), scope, len(data))
		digest.Write(data)
		return nil
	}
	previous := ""
	for _, rule := range m.gitAncestors {
		if !validGitScope(rule.Scope) || !underGitScope(m.gitRoot, rule.Scope) || (previous != "" && !underGitScope(rule.Scope, previous)) {
			return parseError(fmt.Errorf("invalid ancestor Git scope %q", rule.Scope))
		}
		if err := add(rule.Scope, []byte(rule.Content)); err != nil {
			return parseError(err)
		}
		previous = rule.Scope
	}
	var names []string
	err := m.fs.Walk(".", func(name string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if name != "." && (fs.IsInternal(name) || fs.IsTemporary(name) || filepath.Base(name) == ".git") {
			if info.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Base(name) == ".gitignore" {
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return parseError(err)
	}
	sort.Strings(names)
	read := func(name string) ([]byte, error) {
		info, err := m.fs.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !info.IsRegular() || info.IsSymlink() {
			return nil, fmt.Errorf("Git control %s is not a regular file", name)
		}
		file, err := m.fs.Open(name)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return io.ReadAll(file)
	}
	for _, name := range names {
		data, err := read(name)
		if err != nil {
			return parseError(err)
		}
		scope := path.Dir(filepath.ToSlash(name))
		if scope == "." {
			scope = ""
		}
		scope = path.Join(m.gitRoot, scope)
		if scope == "." {
			scope = ""
		}
		if err := add(scope, data); err != nil {
			return parseError(err)
		}
	}
	data, err := read(".syncignore")
	if err != nil && !fs.IsNotExist(err) {
		return parseError(err)
	}
	fmt.Fprintf(digest, "local-present:%t:%d:", err == nil, len(data))
	digest.Write(data)
	next.local, err = parseGit(data)
	if err != nil {
		return parseError(err)
	}
	m.git = next
	m.curHash = hex.EncodeToString(digest.Sum(nil))
	return nil
}

func (g *gitRules) commonIgnored(name string, isDir bool) bool {
	ignored := false
	for _, rule := range g.common {
		if !underGitScope(name, rule.scope) {
			continue
		}
		relative := strings.TrimPrefix(name, rule.scope)
		relative = strings.TrimPrefix(relative, "/")
		if match := rule.matcher.Relative(relative, isDir); match != nil {
			ignored = match.Ignore()
		}
	}
	return ignored
}
func (m *Matcher) gitMatchLocked(file string, isDir bool) ignoreresult.R {
	file = filepath.ToSlash(file)
	if file == ".syncignore" || m.git == nil {
		return ignoreresult.IgnoreAndSkip
	}
	if m.gitRoot != "" {
		ancestors := strings.Split(m.gitRoot, "/")
		for i := 1; i <= len(ancestors); i++ {
			if m.git.commonIgnored(strings.Join(ancestors[:i], "/"), true) {
				return ignoreresult.IgnoreAndSkip
			}
		}
	}
	parts := strings.Split(file, "/")
	// Excluded parents cannot be re-included by a descendant's negation.
	for i := 1; i <= len(parts); i++ {
		relative := strings.Join(parts[:i], "/")
		directory := i < len(parts) || isDir
		logical := path.Join(m.gitRoot, relative)
		if m.git.commonIgnored(logical, directory) {
			return ignoreresult.IgnoreAndSkip
		}
		if match := m.git.local.Relative(relative, directory); match != nil && match.Ignore() {
			return ignoreresult.IgnoreAndSkip
		}
	}
	return ignoreresult.NotIgnored
}

// MatchEntry uses the known entry kind, including not-yet-downloaded directories.
func (m *Matcher) MatchEntry(file string, isDir bool) ignoreresult.R {
	if !m.gitEnabled {
		return m.Match(file)
	}
	if fs.IsTemporary(file) || fs.IsInternal(file) {
		return ignoreresult.IgnoreAndSkip
	}
	if file == "." {
		return ignoreresult.NotIgnored
	}
	m.mut.Lock()
	defer m.mut.Unlock()
	return m.gitMatchLocked(file, isDir)
}

// WatchMatcher sees all Git control changes independently of content exclusion.
// Watching the complete tree also discovers new nested controls under ignored paths.
func (m *Matcher) WatchMatcher() fs.Matcher {
	if m.gitEnabled {
		return gitControlWatcher{}
	}
	return m
}

type gitControlWatcher struct{}

func (gitControlWatcher) Match(string) ignoreresult.R { return ignoreresult.NotIgnored }

// loadAcknowledgedGit parses only bytes of one acknowledged immutable snapshot.
func (m *Matcher) loadAcknowledgedGit() error {
	lease, err := domunerules.Acquire(m.fs.URI())
	if err != nil {
		return parseError(err)
	}
	defer lease.Close()
	context := lease.Context()
	next := &gitRules{}
	logical := context["logicalRoot"].(string)
	add := func(scope, content string) error {
		matcher, err := parseGit([]byte(content))
		if err != nil {
			return err
		}
		next.common = append(next.common, scopedGitRule{scope, matcher})
		return nil
	}
	for _, item := range context["ancestors"].([]any) {
		rule := item.(map[string]any)
		if err := add(rule["scope"].(string), rule["content"].(string)); err != nil {
			return parseError(err)
		}
	}
	controls := context["controls"].(map[string]any)
	names := make([]string, 0, len(controls))
	for name := range controls {
		if name != ".syncignore" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if controls[name] == nil {
			continue
		}
		scope := path.Join(logical, path.Dir(name))
		if scope == "." {
			scope = ""
		}
		if err := add(scope, controls[name].(string)); err != nil {
			return parseError(err)
		}
	}
	next.local, err = parseGit([]byte(controls[".syncignore"].(string)))
	if err != nil {
		return parseError(err)
	}
	if err := lease.Check(); err != nil {
		return parseError(err)
	}
	m.mut.Lock()
	defer m.mut.Unlock()
	m.git = next
	m.gitRoot = logical
	m.curHash = lease.Generation()
	return nil
}
