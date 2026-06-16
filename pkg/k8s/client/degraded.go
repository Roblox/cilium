// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// k8sVersionSnapshotFile is the file (relative to the runtime state directory)
// used to persist the detected apiserver version so that a degraded start can
// restore server capabilities without contacting the apiserver.
const k8sVersionSnapshotFile = "k8s-version.state"

func k8sVersionSnapshotPath() string {
	dir := option.Config.RunDir
	if dir == "" {
		dir = "/var/run/cilium"
	}
	return filepath.Join(dir, k8sVersionSnapshotFile)
}

// saveK8sVersionSnapshot persists the detected apiserver version. It is
// best-effort: failures are logged but not fatal.
func saveK8sVersionSnapshot(logger *slog.Logger, version string) {
	version = strings.TrimSpace(version)
	if version == "" {
		return
	}
	path := k8sVersionSnapshotPath()
	if err := os.WriteFile(path, []byte(version), 0o600); err != nil {
		logger.Warn("Failed to persist Kubernetes apiserver version snapshot",
			logfields.Path, path, logfields.Error, err)
	}
}

// loadK8sVersionSnapshot returns the previously persisted apiserver version, if
// any was recorded by a prior (healthy) start.
func loadK8sVersionSnapshot() (string, bool) {
	b, err := os.ReadFile(k8sVersionSnapshotPath())
	if err != nil {
		return "", false
	}
	version := strings.TrimSpace(string(b))
	if version == "" {
		return "", false
	}
	return version, true
}
