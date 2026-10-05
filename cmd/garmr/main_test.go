// cmd/garmr/main_test.go
package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestInitConfig_HomeDirPath(t *testing.T) {
	// cfgFile empty → falls through to home-dir discovery.
	orig := cfgFile
	cfgFile = ""
	defer func() { cfgFile = orig }()

	// Should not panic even if no config file exists.
	initConfig()
}

func TestInitConfig_ExplicitFile(t *testing.T) {
	orig := cfgFile
	path := writeTempFile(t, "cfg.yaml", "server: http://example.test\n")
	cfgFile = path
	defer func() { cfgFile = orig }()

	initConfig()
}

// A deny and an outage must not share an exit code, or CI cannot tell "the
// policy said no" from "the check never ran".
func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, 0},
		{"operational error", errors.New("evaluation failed: connection refused"), exitError},
		{"negative result", resultError{errors.New("2 test(s) failed")}, exitNegative},
		{"wrapped negative result", fmt.Errorf("suite: %w", resultError{errors.New("failed")}), exitNegative},
	}
	for _, tc := range cases {
		if got := exitCode(tc.err); got != tc.want {
			t.Errorf("%s: exitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}
