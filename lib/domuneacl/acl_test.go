// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0
package domuneacl

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/syncthing/syncthing/lib/protocol"
)

func aclDocument(root string, id protocol.DeviceID, paths []entry) []byte {
	raw, _ := json.Marshal(document{Version: "domune-sync-acl/v1", Root: root, Revision: "one", Devices: []device{{DeviceID: id.String(), Paths: paths}}})
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

func TestACLRejectsInvalidProjectionWithoutReplacingSnapshot(t *testing.T) {
	t.Setenv("DOMUNE_RULES_DIR", t.TempDir())
	root := t.TempDir()
	id := protocol.NewDeviceID([]byte("device"))
	if err := Apply(root, aclDocument(root, id, []entry{{Path: "shared", Read: true, Write: false}})); err != nil {
		t.Fatal(err)
	}
	invalid := []document{
		{Version: "domune-sync-acl/v1", Root: filepath.Join(root, "other"), Revision: "two"},
		{Version: "domune-sync-acl/v1", Root: root, Revision: "two", Devices: []device{{DeviceID: id.String(), Paths: []entry{{Path: "../shared", Read: true}}}}},
		{Version: "domune-sync-acl/v1", Root: root, Revision: "two", Devices: []device{{DeviceID: id.String()}, {DeviceID: id.String()}}},
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
