// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

// Package domunerules installs immutable, schema-validated rule generations.
// Its leases drain engine work during updates. Checks detect external control
// changes; they do not make arbitrary external filesystem writes transactional.
package domunerules

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	gitignore "github.com/denormal/go-gitignore"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaJSON is generated from Domune's contracts/schemas/sync-rule-context.schema.json.
//
//go:embed schema.json
var schemaJSON []byte
var schema = func() *jsonschema.Schema {
	var value any
	if err := json.Unmarshal(schemaJSON, &value); err != nil {
		panic(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("https://domune.invalid/rules", value); err != nil {
		panic(err)
	}
	s, err := c.Compile("https://domune.invalid/rules")
	if err != nil {
		panic(err)
	}
	return s
}()

type generation struct {
	data     map[string]any
	raw      []byte
	identity string
}
type gate struct {
	mu              sync.RWMutex
	current         *generation
	epoch           atomic.Uint64
	authorizedEpoch uint64
}

var gates sync.Map

func Enabled() bool { return os.Getenv("DOMUNE_RULES_DIR") != "" }
func state(root string) *gate {
	key := os.Getenv("DOMUNE_RULES_DIR") + "\x00" + root
	g, _ := gates.LoadOrStore(key, &gate{})
	return g.(*gate)
}
func contextPath(root string) string {
	sum := sha256.Sum256([]byte(root))
	return filepath.Join(os.Getenv("DOMUNE_RULES_DIR"), hex.EncodeToString(sum[:])+".json")
}
func validScope(s string) bool {
	return s == "" || (path.Clean(s) == s && !path.IsAbs(s) && s != ".." && !strings.HasPrefix(s, "../") && !strings.ContainsAny(s, "\\\x00"))
}
func within(name, scope string) bool { return scope == "" || strings.HasPrefix(name, scope+"/") }
func decode(root string, raw []byte) (*generation, error) {
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	if err := schema.Validate(data); err != nil {
		return nil, err
	}
	if data["root"] != root || !filepath.IsAbs(root) || !validScope(data["logicalRoot"].(string)) {
		return nil, fmt.Errorf("invalid rule root")
	}
	logical := data["logicalRoot"].(string)
	previous := ""
	for i, item := range data["ancestors"].([]any) {
		rule := item.(map[string]any)
		scope := rule["scope"].(string)
		if !validScope(scope) || !within(logical, scope) || (i > 0 && !within(scope, previous)) {
			return nil, fmt.Errorf("invalid ancestor scope")
		}
		previous = scope
	}
	for name := range data["controls"].(map[string]any) {
		if name != ".syncignore" && name != ".gitignore" && (!validScope(name) || path.Base(name) != ".gitignore") {
			return nil, fmt.Errorf("invalid control path %q", name)
		}
	}
	contents := []string{}
	for _, item := range data["ancestors"].([]any) {
		contents = append(contents, item.(map[string]any)["content"].(string))
	}
	for _, value := range data["controls"].(map[string]any) {
		if value != nil {
			contents = append(contents, value.(string))
		}
	}
	for _, content := range contents {
		var failure error
		gitignore.New(strings.NewReader(content), "", func(err gitignore.Error) bool { failure = err; return false })
		if failure != nil {
			return nil, failure
		}
	}
	canonical, _ := json.Marshal(data)
	sum := sha256.Sum256(canonical)
	return &generation{data: data, raw: canonical, identity: hex.EncodeToString(sum[:])}, nil
}
func (g *generation) check() error {
	root := g.data["root"].(string)
	controls := g.data["controls"].(map[string]any)
	seen := make(map[string]bool)
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == ".stfolder" || entry.Name() == ".stversions") {
			return filepath.SkipDir
		}
		name := entry.Name()
		if strings.Contains(name, "sync-conflict") && (strings.HasPrefix(name, ".gitignore") || strings.HasPrefix(name, ".syncignore") || strings.HasSuffix(name, ".gitignore") || strings.HasSuffix(name, ".syncignore")) {
			return fmt.Errorf("conflicting rule %s", rel)
		}
		if name != ".gitignore" && rel != ".syncignore" {
			return nil
		}
		expected, ok := controls[rel]
		if !ok || expected == nil {
			return fmt.Errorf("unacknowledged control %s", rel)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("nonregular control %s", rel)
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		if string(data) != expected.(string) {
			return fmt.Errorf("stale control %s", rel)
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	for name, content := range controls {
		if content != nil && !seen[name] {
			return fmt.Errorf("missing control %s", name)
		}
	}
	return nil
}

// Apply is called only by the authenticated management endpoint with the folder
// paused. Waiting for the exclusive gate drains all outstanding core leases.
func Apply(root string, raw []byte) error {
	if !Enabled() {
		return fmt.Errorf("Domune rules are not enabled")
	}
	next, err := decode(root, raw)
	if err != nil {
		return err
	}
	g := state(root)
	g.mu.Lock()
	defer g.mu.Unlock()
	epoch := g.epoch.Load()
	if err := next.check(); err != nil {
		return err
	}
	dir := os.Getenv("DOMUNE_RULES_DIR")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".rules-")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err = file.Write(next.raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temp, contextPath(root)); err != nil {
		return err
	}
	g.current = next
	g.authorizedEpoch = epoch
	if next.needsAuthority() && g.epoch.Load() != epoch {
		return fmt.Errorf("connection changed during rule confirmation")
	}
	return nil
}

type Lease struct {
	gate     *gate
	snapshot *generation
	epoch    uint64
}

func Acquire(root string) (*Lease, error) {
	if !Enabled() {
		return &Lease{}, nil
	}
	g := state(root)
	g.mu.RLock()
	if g.current == nil {
		g.mu.RUnlock()
		return nil, fmt.Errorf("rule context requires fresh authority confirmation after startup")
	}
	lease := &Lease{gate: g, snapshot: g.current, epoch: g.authorizedEpoch}
	if err := lease.Check(); err != nil {
		lease.Close()
		return nil, err
	}
	return lease, nil
}
func (l *Lease) Close() {
	if l.gate != nil {
		l.gate.mu.RUnlock()
		l.gate = nil
	}
}
func (l *Lease) Check() error {
	if l.snapshot == nil {
		return nil
	}
	if l.snapshot.needsAuthority() && l.gate.epoch.Load() != l.epoch {
		return fmt.Errorf("rule context requires fresh authority confirmation after disconnect")
	}
	return l.snapshot.check()
}
func (l *Lease) Generation() string {
	if l.snapshot == nil {
		return ""
	}
	return l.snapshot.identity
}

// Context returns a fresh copy; callers cannot mutate an installed generation.
func (l *Lease) Context() map[string]any {
	if l.snapshot == nil {
		return nil
	}
	var data map[string]any
	_ = json.Unmarshal(l.snapshot.raw, &data)
	return data
}
func Ready(root string) error {
	lease, err := Acquire(root)
	if err != nil {
		return err
	}
	lease.Close()
	return nil
}

// Invalidate is nonblocking: connection callbacks may hold model locks needed by
// active workers. Epoch checks stop those workers; the next Apply drains them.
func Invalidate(root string) {
	if Enabled() {
		state(root).epoch.Add(1)
	}
}
func (l *Lease) RequestGeneration() string {
	if l.snapshot == nil {
		return ""
	}
	return l.snapshot.data["generation"].(string)
}

func (g *generation) needsAuthority() bool {
	return g.data["logicalRoot"].(string) != "" || len(g.data["ancestors"].([]any)) != 0
}
