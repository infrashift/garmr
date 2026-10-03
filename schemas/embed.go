// Package schemas embeds the canonical Garmr policy schema so that the engine,
// the CLI, and `cue vet` all validate against the same source of truth.
package schemas

import _ "embed"

// PolicyCUE is the contents of policy.cue, the schema every policy document is
// unified with before it is compiled — whether it arrives via LoadPolicy,
// /v1/validate, or the --policy-dir directory loader.
//
//go:embed policy.cue
var PolicyCUE string
