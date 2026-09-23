// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

package model

import (
	"fmt"
	"reflect"

	"github.com/syncthing/syncthing/lib/domuneacl"
	"github.com/syncthing/syncthing/lib/protocol"
)

// incomingACL binds a pending global item to an authenticated device index
// that still has write permission. A retained global index or a matching
// local/temporary block is never authority by itself.
func (f *sendReceiveFolder) incomingACL(file protocol.FileInfo) (*domuneacl.Lease, error) {
	lease, err := domuneacl.Acquire(f.Path)
	if err != nil || !domuneacl.Enabled() {
		return lease, err
	}
	if f.model == nil || f.model.sdb == nil {
		lease.Close()
		return nil, fmt.Errorf("ACL cannot verify index source for %q", file.Name)
	}
	global, ok, err := f.model.sdb.GetGlobalFile(f.folderID, file.Name)
	if err != nil || !ok || !sameIncomingFile(global, file) {
		lease.Close()
		return nil, fmt.Errorf("ACL stale global index for %q: %v", file.Name, err)
	}
	devices, err := f.model.sdb.GetGlobalAvailability(f.folderID, file.Name)
	if err != nil {
		lease.Close()
		return nil, err
	}
	for _, device := range devices {
		if !lease.Allows(device, file.Name, true) {
			continue
		}
		indexed, ok, err := f.model.sdb.GetDeviceFile(f.folderID, device, file.Name)
		if err != nil {
			lease.Close()
			return nil, err
		}
		if ok && sameIncomingFile(indexed, file) {
			if err := lease.Check(); err != nil {
				lease.Close()
				return nil, err
			}
			return lease, nil
		}
	}
	lease.Close()
	return nil, fmt.Errorf("ACL denied retained index for %q", file.Name)
}

func sameIncomingFile(a, b protocol.FileInfo) bool {
	if !a.Version.Equal(b.Version) || !a.IsEquivalent(b, 0) || !a.BlocksEqual(b) {
		return false
	}
	a.Sequence, b.Sequence = 0, 0
	a.LocalFlags, b.LocalFlags = 0, 0
	a.New, b.New = false, false
	return reflect.DeepEqual(a, b)
}
