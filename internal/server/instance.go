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
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
)

var (
	instanceIDOnce sync.Once
	instanceID     string
)

// InstanceID returns a stable identifier for this process.
func InstanceID() string {
	instanceIDOnce.Do(func() {
		instanceID = resolveInstanceID(os.Getenv, os.Hostname, os.Getpid())
	})
	return instanceID
}

// resolveInstanceID prefers the orchestrator's own allocation identity, which
// is what an operator correlates against logs and `nomad alloc status`.
// Without one it falls back to the hostname (the container ID under most
// runtimes) qualified by the PID, and finally to a random UUID, so the value
// is never empty.
//
// The PID matters: a hostname alone names a machine, not a process, and two
// instances on one host (systemd units, a raw_exec job without alloc
// variables, a laptop) would report the same ID, so --converge would count
// them as one instance and wait for a second that never appears, or worse,
// accept one instance's acknowledgement for both.
func resolveInstanceID(getenv func(string) string, hostname func() (string, error), pid int) string {
	for _, env := range []string{"NOMAD_ALLOC_ID", "NOMAD_SHORT_ALLOC_ID"} {
		if v := getenv(env); v != "" {
			return v
		}
	}
	host := getenv("HOSTNAME")
	if host == "" {
		if h, err := hostname(); err == nil {
			host = h
		}
	}
	if host != "" {
		return fmt.Sprintf("%s:%d", host, pid)
	}
	return uuid.New().String()
}
