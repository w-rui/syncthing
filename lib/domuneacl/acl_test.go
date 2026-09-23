// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package domuneacl

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/syncthing/syncthing/lib/protocol"
)

func aclDocument(root string, id protocol.DeviceID, paths []entry) []byte {
	raw, _ := json.Marshal(document{Version: "domune-sync-acl/v1", Root: root, InstanceID: instanceID, Generation: 1, Revision: "one", Devices: []device{{DeviceID: id.String(), Paths: paths}}})
	return raw
}

func TestACLDefaultDenyAndLongestPath(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	id := protocol.NewDeviceID([]byte("known device"))
	if lease, err := Acquire(root); err == nil {
		lease.Close()
		t.Fatal("missing ACL accepted")
	}
	raw := aclDocument(root, id, []entry{{Path: "", Read: true, Write: false}, {Path: "private", Read: false, Write: false}, {Path: "shared", Read: true, Write: true}})
	if err := Apply(root, raw); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	for _, tc := range []struct {
		path    string
		write   bool
		allowed bool
	}{
		{"public/file", false, true}, {"public/file", true, false},
		{"private/secret", false, false}, {"private/secret", true, false},
		{"shared/file", true, true}, {"sharedness/file", true, false},
		{"shared/../private/secret", false, false}, {"../shared/file", false, false},
	} {
		if got := lease.Allows(id, tc.path, tc.write); got != tc.allowed {
			t.Errorf("%q write=%t: got %t, want %t", tc.path, tc.write, got, tc.allowed)
		}
	}
	if lease.Allows(protocol.NewDeviceID([]byte("unknown device")), "public/file", false) {
		t.Fatal("unknown device allowed")
	}
}

func TestACLNarrowerRestrictionSurvivesDeeperRegrant(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	id := protocol.NewDeviceID([]byte("known device"))
	raw := aclDocument(root, id, []entry{
		{Path: "", Read: true, Write: true},
		{Path: "shared/private", Read: true, Write: false},
		{Path: "shared/private/public", Read: true, Write: true},
	})
	if err := Apply(root, raw); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if !lease.HasNarrowerWriteRestriction(id, "shared") {
		t.Fatal("deep rw regrant hid intermediate readonly restriction")
	}
	if lease.HasNarrowerWriteRestriction(id, "shared/allowed") {
		t.Fatal("unrestricted sibling was blocked")
	}
	if lease.HasNarrowerWriteRestriction(id, "shared/private/public") {
		t.Fatal("direct regranted subtree was blocked by its ancestor")
	}
}

func TestACLSubtreeGrantNeedsNoBroadAncestor(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	id := protocol.NewDeviceID([]byte("known device"))
	raw := aclDocument(root, id, []entry{{Path: "shared/allowed", Read: true, Write: true}})
	if err := Apply(root, raw); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if lease.Allows(id, "shared", false) || !lease.Allows(id, "shared/allowed/file", true) || lease.Allows(id, "shared/sibling/file", false) {
		t.Fatal("subtree grant required broad ancestor or exposed sibling")
	}
}

func TestACLRejectsInvalidProjectionWithoutReplacingSnapshot(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	id := protocol.NewDeviceID([]byte("device"))
	if err := Apply(root, aclDocument(root, id, []entry{{Path: "shared", Read: true, Write: false}})); err != nil {
		t.Fatal(err)
	}
	invalid := []document{
		{Version: "domune-sync-acl/v1", Root: filepath.Join(root, "other"), InstanceID: instanceID, Generation: 2, Revision: "two"},
		{Version: "domune-sync-acl/v1", Root: root, InstanceID: instanceID, Generation: 2, Revision: "two", Devices: []device{{DeviceID: id.String(), Paths: []entry{{Path: "../shared", Read: true}}}}},
		{Version: "domune-sync-acl/v1", Root: root, InstanceID: instanceID, Generation: 2, Revision: "two", Devices: []device{{DeviceID: id.String()}, {DeviceID: id.String()}}},
	}
	for _, item := range invalid {
		raw, _ := json.Marshal(item)
		if err := Apply(root, raw); err == nil {
			t.Errorf("invalid projection accepted: %+v", item)
		}
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if lease.Revision() != "one" || !lease.Allows(id, "shared/file", false) {
		t.Fatal("invalid projection replaced current ACL")
	}
}

func TestACLGenerationReplayAndBusyApply(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	id := protocol.NewDeviceID([]byte("known device"))
	first := aclDocument(root, id, []entry{{Path: "shared", Read: true, Write: true}})
	if status := Readiness(root); status.Ready || status.Generation != 0 || status.InstanceID == "" {
		t.Fatalf("unexpected fresh state: %+v", status)
	}
	if err := Apply(root, first); err != nil {
		t.Fatal(err)
	}
	lease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	next := document{Version: "domune-sync-acl/v1", Root: root, InstanceID: instanceID, Generation: 2, Revision: "two", Devices: []device{}}
	raw, _ := json.Marshal(next)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := ApplyContext(ctx, root, raw); err == nil {
		t.Fatal("busy apply falsely acknowledged")
	}
	if got := Readiness(root).Generation; got != 1 {
		t.Fatalf("busy apply replaced generation: %d", got)
	}
	lease.Close()
	if err := Apply(root, raw); err != nil {
		t.Fatal(err)
	}
	if err := Apply(root, first); err == nil {
		t.Fatal("older generation replay accepted")
	}
	if err := Apply(root, raw); err != nil {
		t.Fatalf("identical generation retry rejected: %v", err)
	}
	next.Devices = []device{{DeviceID: id.String(), Paths: []entry{{Path: "shared", Read: true}}}}
	changed, _ := json.Marshal(next)
	if err := Apply(root, changed); err == nil {
		t.Fatal("same generation different content accepted")
	}
	next.Generation = 3
	changed, _ = json.Marshal(next)
	if err := Apply(root, changed); err == nil {
		t.Fatal("same revision different content accepted")
	}
	next.InstanceID = "00000000000000000000000000000000"
	next.Revision = "three"
	changed, _ = json.Marshal(next)
	if err := Apply(root, changed); err == nil {
		t.Fatal("old core instance accepted")
	}
	staleLease, err := Acquire(root)
	if err != nil {
		t.Fatal(err)
	}
	Invalidate(root)
	if err := staleLease.Check(); err == nil || staleLease.Allows(id, "shared/file", false) {
		t.Fatal("in-flight lease stayed valid after disconnect")
	}
	staleLease.Close()
	if Readiness(root).Ready {
		t.Fatal("disconnected ACL still ready")
	}
	if _, err := Acquire(root); err == nil {
		t.Fatal("old connection projection accepted")
	}
	if err := Apply(root, raw); err != nil {
		t.Fatalf("same content reack after disconnect failed: %v", err)
	}
}
