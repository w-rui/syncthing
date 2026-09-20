// Copyright (C) 2026 The Syncthing Authors.
// SPDX-License-Identifier: MPL-2.0

// Probe only: external manifest tests control/data readiness boundaries.
// This is not a released configuration or a Git-ignore implementation.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/syncthing/syncthing/lib/domunerules"
	"os"
	"path/filepath"
	"strings"
)

func domuneProbeRulesReady(root string) error {
	if domunerules.Enabled() {
		return domunerules.Ready(root)
	}
	path := os.Getenv("DOMUNE_RULE_PROBE")
	if path == "" {
		return nil
	}
	fail := func(err error) error { return fmt.Errorf("domune probe rules not ready: %w", err) }
	data, err := os.ReadFile(path)
	if err != nil {
		return fail(err)
	}
	var manifest struct {
		Root       string            `json:"root"`
		Generation string            `json:"generation"`
		Rules      map[string]string `json:"rules"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fail(err)
	}
	if manifest.Root != root || manifest.Generation == "" {
		return fail(fmt.Errorf("root or generation mismatch"))
	}
	for _, name := range []string{".stignore", ".gitignore", ".syncignore"} {
		if _, ok := manifest.Rules[name]; !ok {
			return fail(fmt.Errorf("missing rule entry %s", name))
		}
	}
	for name, expected := range manifest.Rules {
		if !filepath.IsLocal(name) || strings.Contains(name, "\\") {
			return fail(fmt.Errorf("invalid scope %s", name))
		}
		info, err := os.Lstat(filepath.Join(root, name))
		if os.IsNotExist(err) && expected == "absent" {
			continue
		}
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() {
			return fail(fmt.Errorf("non-regular rule %s", name))
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return fail(err)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			return fail(fmt.Errorf("stale rule %s", name))
		}
	}
	return nil
}

// Content work is pinned to the matcher's acknowledged generation. A stale
// queued job cannot become valid merely because a newer context was installed.
func domuneLease(root, generation string) (*domunerules.Lease, error) {
	lease, err := domunerules.Acquire(root)
	if err != nil {
		return nil, err
	}
	if domunerules.Enabled() && lease.Generation() != generation {
		lease.Close()
		return nil, fmt.Errorf("stale rule generation")
	}
	return lease, nil
}
