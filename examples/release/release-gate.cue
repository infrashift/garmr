// examples/release/release-gate.cue
// Production Release Gate Policy
package release

releaseGate: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "release-gate"
        namespace: "release"
    }
    spec: {
        description: "Production release gate requirements"
        target: {
            resources: ["deployment", "release"]
        }
        rules: [
            {
                id: "REL-001"
                description: "All tests must pass"
                severity: "critical"
                expr: {
                    match: {
                        path: "tests.passed"
                        equals: true
                    }
                }
                message: "Tests have not passed"
            },
            {
                id: "REL-002"
                description: "No test failures allowed"
                severity: "critical"
                expr: {
                    match: {
                        path: "tests.failures"
                        equals: 0
                    }
                }
                message: "There are test failures"
            },
            {
                id: "REL-003"
                description: "Code coverage must be at least 80%"
                severity: "high"
                expr: {
                    match: {
                        path: "coverage"
                        greaterThanOrEqual: 80
                    }
                }
                message: "Code coverage is below 80%"
            },
            {
                id: "REL-004"
                description: "No critical security findings"
                severity: "critical"
                expr: {
                    match: {
                        path: "security.criticalFindings"
                        equals: 0
                    }
                }
                message: "Critical security findings detected"
            },
            {
                id: "REL-005"
                description: "Artifact must be signed"
                severity: "critical"
                expr: {
                    match: {
                        path: "artifact.signed"
                        equals: true
                    }
                }
                message: "Artifact is not signed"
            }
        ]
        enforcement: {
            action: "deny"
            failFast: true
        }
    }
}
