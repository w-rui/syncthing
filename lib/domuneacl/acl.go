// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

// Package domuneacl holds a separately acknowledged device/path authorization
// snapshot. The authenticated peer identity comes from the BEP connection.
package domuneacl

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/syncthing/syncthing/lib/domunerules"
	"github.com/syncthing/syncthing/lib/protocol"
)

//go:embed schema.json
var schemaJSON []byte
var schema = func() *jsonschema.Schema {
	var document any
	if err := json.Unmarshal(schemaJSON, &document); err != nil {
		panic(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("https://domune.invalid/acl", document); err != nil {
		panic(err)
	}
	result, err := compiler.Compile("https://domune.invalid/acl")
	if err != nil {
		panic(err)
	}
	return result
}()

type entry struct {
	Path  string `json:"path"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
}
type device struct {
	DeviceID string  `json:"deviceID"`
	Paths    []entry `json:"paths"`
}
type document struct {
	Version    string   `json:"version"`
	Root       string   `json:"root"`
	InstanceID string   `json:"instanceId"`
	Generation int64    `json:"generation"`
	Revision   string   `json:"revision"`
	Devices    []device `json:"devices"`
}
type gate struct {
	mu           sync.RWMutex
	current      *document
	epoch        atomic.Uint64
	appliedEpoch uint64
}

var gates sync.Map
var instanceID = func() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}()

func Enabled() bool { return domunerules.Enabled() }
func state(root string) *gate {
	value, _ := gates.LoadOrStore(root, &gate{})
	return value.(*gate)
}
func validPath(name string, root bool) bool {
	if root && name == "" {
		return true
	}
	return name != "" && name != "." && name != ".." && !strings.HasPrefix(name, "/") &&
		!strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00") && path.Clean(name) == name
}

// Apply replaces the in-memory projection while the folder is paused. Nothing
// is trusted from disk at startup: a missing fresh projection stays denied.
func Apply(root string, raw []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return ApplyContext(ctx, root, raw)
}

// ApplyContext never acknowledges a projection while an earlier operation
// still holds a lease. A busy operation leaves the previous ACL unchanged.
func ApplyContext(ctx context.Context, root string, raw []byte) error {
	if !Enabled() {
		return fmt.Errorf("Domune ACL requires managed rules")
	}
	var input any
	if err := json.Unmarshal(raw, &input); err != nil {
		return err
	}
	if err := schema.Validate(input); err != nil {
		return err
	}
	var next document
	if err := json.Unmarshal(raw, &next); err != nil {
		return err
	}
	if next.Root != root || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("invalid ACL root")
	}
	if next.InstanceID != instanceID {
		return fmt.Errorf("ACL projection belongs to another core instance")
	}
	seenDevices := make(map[protocol.DeviceID]bool)
	for _, member := range next.Devices {
		id, err := protocol.DeviceIDFromString(member.DeviceID)
		if err != nil || id.String() != member.DeviceID || seenDevices[id] {
			return fmt.Errorf("invalid or duplicate ACL device")
		}
		seenDevices[id] = true
		seenPaths := make(map[string]bool)
		for _, item := range member.Paths {
			if !validPath(item.Path, true) || seenPaths[item.Path] {
				return fmt.Errorf("invalid or duplicate ACL path %q", item.Path)
			}
			seenPaths[item.Path] = true
		}
	}
	g := state(root)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !g.mu.TryLock() {
		select {
		case <-ctx.Done():
			return fmt.Errorf("ACL application not completed: %w", ctx.Err())
		case <-ticker.C:
		}
	}
	defer g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ACL application not completed: %w", err)
	}
	if g.current != nil {
		if next.Generation < g.current.Generation {
			return fmt.Errorf("stale ACL generation")
		}
		if next.Generation == g.current.Generation && !sameDocument(&next, g.current) {
			return fmt.Errorf("ACL generation already used for different content")
		}
		if next.Revision == g.current.Revision && !sameContent(&next, g.current) {
			return fmt.Errorf("ACL revision already used for different content")
		}
	}
	g.current = &next
	g.appliedEpoch = g.epoch.Load()
	return nil
}

func sameContent(a, b *document) bool {
	ac, bc := *a, *b
	ac.Generation, bc.Generation = 0, 0
	return reflect.DeepEqual(ac, bc)
}

func sameDocument(a, b *document) bool { return reflect.DeepEqual(a, b) }

// Lease holds a consistent authorization snapshot across a protocol operation.
// Apply waits until every active lease is closed.
type Lease struct {
	gate     *gate
	snapshot *document
	epoch    uint64
}

type Status struct {
	InstanceID string `json:"instanceId"`
	Generation int64  `json:"generation"`
	Revision   string `json:"revision,omitempty"`
	Ready      bool   `json:"ready"`
}

func Readiness(root string) Status {
	result := Status{InstanceID: instanceID}
	if !Enabled() {
		return result
	}
	g := state(root)
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.current != nil {
		result.Generation = g.current.Generation
		result.Revision = g.current.Revision
		result.Ready = g.appliedEpoch == g.epoch.Load()
	}
	return result
}

// Invalidate prevents a disconnected peer from using a projection from its
// previous connection. It does not wait while model locks are held.
func Invalidate(root string) {
	if Enabled() {
		state(root).epoch.Add(1)
	}
}

func Acquire(root string) (*Lease, error) {
	if !Enabled() {
		return &Lease{}, nil
	}
	g := state(root)
	g.mu.RLock()
	epoch := g.epoch.Load()
	if g.current == nil || g.appliedEpoch != epoch {
		g.mu.RUnlock()
		return nil, fmt.Errorf("ACL requires fresh authority confirmation")
	}
	return &Lease{gate: g, snapshot: g.current, epoch: epoch}, nil
}
func (l *Lease) Close() {
	if l.gate != nil {
		l.gate.mu.RUnlock()
		l.gate = nil
	}
}
func (l *Lease) Revision() string {
	if l.snapshot == nil {
		return ""
	}
	return l.snapshot.Revision
}
func (l *Lease) Allows(id protocol.DeviceID, name string, write bool) bool {
	if l.snapshot == nil {
		return true
	}
	if l.gate.epoch.Load() != l.epoch {
		return false
	}
	if !validPath(name, false) {
		return false
	}
	for _, member := range l.snapshot.Devices {
		if member.DeviceID != id.String() {
			continue
		}
		var selected *entry
		for i := range member.Paths {
			candidate := &member.Paths[i]
			if candidate.Path == "" || name == candidate.Path || strings.HasPrefix(name, candidate.Path+"/") {
				if selected == nil || len(candidate.Path) > len(selected.Path) {
					selected = candidate
				}
			}
		}
		if selected == nil {
			return false
		}
		if write {
			return selected.Write
		}
		return selected.Read
	}
	return false
}

func (l *Lease) Check() error {
	if l.gate != nil && l.gate.epoch.Load() != l.epoch {
		return fmt.Errorf("ACL connection generation invalidated")
	}
	return nil
}
