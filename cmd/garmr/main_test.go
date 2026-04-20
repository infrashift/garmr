// cmd/garmr/main_test.go
package main

import (
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
