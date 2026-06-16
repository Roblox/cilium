// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"

	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// localNodeSnapshotFile is the file (relative to the runtime state directory)
// used to persist the local node so that it can be restored during a degraded
// start when the Kubernetes apiserver is unreachable.
const localNodeSnapshotFile = "local_node.state"

// degradedLocalNodeInitTimeout bounds how long InitLocalNode waits for the
// apiserver before falling back to the on-disk snapshot during a degraded
// start. Healthy clusters return well within this window (the node Upsert
// event arrives in seconds); only a true apiserver outage hits the timeout.
const degradedLocalNodeInitTimeout = 30 * time.Second

// degradedStartupGateTimeout bounds how long the daemon start hook waits on
// apiserver-dependent gates (CRD sync, node information) before continuing in
// degraded mode. It exists so that, during an apiserver outage, the agent can
// finish booting -- open its API socket and start the datapath/BGP control
// plane -- instead of blocking (or crashlooping) until the apiserver returns.
// The background reconcilers keep retrying and converge once it is reachable.
const degradedStartupGateTimeout = 30 * time.Second

// localNodeSnapshot is the on-disk, JSON-serializable representation of the
// local node. The embedded nodeTypes.Node round-trips via JSON (the same
// representation used by the node kvstore), and the remaining LocalNode fields
// that are not part of Node are stored explicitly. The slog.Logger is
// intentionally omitted.
type localNodeSnapshot struct {
	Node                  nodeTypes.Node `json:"node"`
	OptOutNodeEncryption  bool           `json:"optOutNodeEncryption,omitempty"`
	UID                   k8stypes.UID   `json:"uid,omitempty"`
	ProviderID            string         `json:"providerID,omitempty"`
	IPv4NativeRoutingCIDR string         `json:"ipv4NativeRoutingCIDR,omitempty"`
	IPv6NativeRoutingCIDR string         `json:"ipv6NativeRoutingCIDR,omitempty"`
	ServiceLoopbackIPv4   string         `json:"serviceLoopbackIPv4,omitempty"`
}

func localNodeSnapshotPath() string {
	dir := option.Config.RunDir
	if dir == "" {
		dir = "/var/run/cilium"
	}
	return filepath.Join(dir, localNodeSnapshotFile)
}

func toLocalNodeSnapshot(ln node.LocalNode) localNodeSnapshot {
	snap := localNodeSnapshot{
		Node:                 ln.Node,
		OptOutNodeEncryption: ln.OptOutNodeEncryption,
		UID:                  ln.UID,
		ProviderID:           ln.ProviderID,
	}
	if ln.IPv4NativeRoutingCIDR != nil {
		snap.IPv4NativeRoutingCIDR = ln.IPv4NativeRoutingCIDR.String()
	}
	if ln.IPv6NativeRoutingCIDR != nil {
		snap.IPv6NativeRoutingCIDR = ln.IPv6NativeRoutingCIDR.String()
	}
	if ln.ServiceLoopbackIPv4 != nil {
		snap.ServiceLoopbackIPv4 = ln.ServiceLoopbackIPv4.String()
	}
	return snap
}

// saveLocalNodeSnapshot atomically persists the local node to disk. It is
// best-effort and only used when degraded start is enabled.
func saveLocalNodeSnapshot(ln node.LocalNode) error {
	data, err := json.Marshal(toLocalNodeSnapshot(ln))
	if err != nil {
		return err
	}
	path := localNodeSnapshotPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// loadLocalNodeSnapshot reads the persisted local node, if any. The boolean
// return is false when no snapshot exists yet.
func loadLocalNodeSnapshot() (localNodeSnapshot, bool, error) {
	data, err := os.ReadFile(localNodeSnapshotPath())
	if err != nil {
		if os.IsNotExist(err) {
			return localNodeSnapshot{}, false, nil
		}
		return localNodeSnapshot{}, false, err
	}
	var snap localNodeSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return localNodeSnapshot{}, false, err
	}
	return snap, true, nil
}

// applyLocalNodeSnapshot overlays a restored snapshot onto the local node.
// The Logger is preserved, and Source/NodeIdentity are reasserted to the
// local-node defaults set by InitLocalNode.
func applyLocalNodeSnapshot(n *node.LocalNode, snap localNodeSnapshot) {
	logger := n.Logger
	n.Node = snap.Node
	n.Logger = logger
	n.OptOutNodeEncryption = snap.OptOutNodeEncryption
	n.UID = snap.UID
	n.ProviderID = snap.ProviderID

	if snap.IPv4NativeRoutingCIDR != "" {
		if c, err := cidr.ParseCIDR(snap.IPv4NativeRoutingCIDR); err == nil {
			n.IPv4NativeRoutingCIDR = c
		}
	}
	if snap.IPv6NativeRoutingCIDR != "" {
		if c, err := cidr.ParseCIDR(snap.IPv6NativeRoutingCIDR); err == nil {
			n.IPv6NativeRoutingCIDR = c
		}
	}
	if snap.ServiceLoopbackIPv4 != "" {
		n.ServiceLoopbackIPv4 = net.ParseIP(snap.ServiceLoopbackIPv4)
	}

	n.Source = source.Local
	n.NodeIdentity = uint32(identity.ReservedIdentityHost)
}
