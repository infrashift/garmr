// internal/server/instance.go
// Per-process instance identity.
//
// Behind a service mesh, callers reach Garmr through an upstream that
// load-balances across every healthy instance. A reload or a digest read
// therefore lands on one arbitrary instance, and the response carries nothing
// to say which. A CI job that reloads through such an upstream sees a single
// success and a single digest and concludes the fleet converged, while the
// instances it never reached go on serving the previous policy set.
//
// Reporting a stable per-process identifier is what makes convergence
// checkable from outside: the caller keeps reloading until it has seen every
// instance acknowledge the expected digest.
package server

import (
	"os"
	"sync"

	"github.com/google/uuid"
)

var (
	instanceIDOnce sync.Once
	instanceID     string
)

// InstanceID returns a stable identifier for this process.
//
// Prefers the orchestrator's own allocation identity, which is what an
// operator correlates against logs and `nomad alloc status`; falls back to the
// hostname (the container ID under most runtimes) and finally to a random
// UUID, so the value is never empty.
func InstanceID() string {
	instanceIDOnce.Do(func() {
		for _, env := range []string{"NOMAD_ALLOC_ID", "NOMAD_SHORT_ALLOC_ID", "HOSTNAME"} {
			if v := os.Getenv(env); v != "" {
				instanceID = v
				return
			}
		}
		if host, err := os.Hostname(); err == nil && host != "" {
			instanceID = host
			return
		}
		instanceID = uuid.New().String()
	})
	return instanceID
}
