// examples/release/dtap-release.cue
// DTAP (Dev/Test/Acceptance/Prod) Release Pipeline Policy
package release

// Development environment - permissive
devGate: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "dev-gate"
        namespace: "release"
        labels: environment: "dev"
    }
    spec: {
        description: "Development environment gate - minimal checks"
        target: resources: ["deployment", "release"]
        rules: [{
            id: "DEV-001"
            description: "Build must complete"
            severity: "high"
            expr: match: {path: "build.completed", equals: true}
            message: "Build has not completed"
        }]
        enforcement: action: "warn"
    }
}

// Test environment - moderate
testGate: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "test-gate"
        namespace: "release"
        labels: environment: "test"
    }
    spec: {
        description: "Test environment gate"
        target: resources: ["deployment", "release"]
        rules: [
            {
                id: "TST-001"
                description: "Unit tests must pass"
                severity: "high"
                expr: match: {path: "tests.unit.passed", equals: true}
                message: "Unit tests have not passed"
            },
            {
                id: "TST-002"
                description: "Code coverage minimum 60%"
                severity: "medium"
                expr: match: {path: "coverage", greaterThanOrEqual: 60}
                message: "Code coverage below 60%"
            }
        ]
        enforcement: action: "deny"
    }
}

// Acceptance environment - strict
acceptanceGate: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "acceptance-gate"
        namespace: "release"
        labels: environment: "acceptance"
    }
    spec: {
        description: "Acceptance environment gate"
        target: resources: ["deployment", "release"]
        rules: [
            {
                id: "ACC-001"
                description: "All tests must pass"
                severity: "critical"
                expr: match: {path: "tests.passed", equals: true}
                message: "Tests have not passed"
            },
            {
                id: "ACC-002"
                description: "Integration tests must pass"
                severity: "high"
                expr: match: {path: "tests.integration.passed", equals: true}
                message: "Integration tests have not passed"
            },
            {
                id: "ACC-003"
                description: "Code coverage minimum 75%"
                severity: "high"
                expr: match: {path: "coverage", greaterThanOrEqual: 75}
                message: "Code coverage below 75%"
            },
            {
                id: "ACC-004"
                description: "No critical security issues"
                severity: "critical"
                expr: match: {path: "security.criticalFindings", equals: 0}
                message: "Critical security findings detected"
            }
        ]
        enforcement: action: "deny"
    }
}

// Production environment - strictest
prodGate: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "prod-gate"
        namespace: "release"
        labels: environment: "prod"
    }
    spec: {
        description: "Production environment gate - strictest requirements"
        target: resources: ["deployment", "release"]
        rules: [
            {
                id: "PRD-001"
                description: "All tests must pass"
                severity: "critical"
                expr: match: {path: "tests.passed", equals: true}
                message: "Tests have not passed"
            },
            {
                id: "PRD-002"
                description: "Code coverage minimum 80%"
                severity: "high"
                expr: match: {path: "coverage", greaterThanOrEqual: 80}
                message: "Code coverage below 80%"
            },
            {
                id: "PRD-003"
                description: "No critical security issues"
                severity: "critical"
                expr: match: {path: "security.criticalFindings", equals: 0}
                message: "Critical security findings detected"
            },
            {
                id: "PRD-004"
                description: "No high security issues"
                severity: "high"
                expr: match: {path: "security.highFindings", lessThan: 5}
                message: "Too many high severity findings"
            },
            {
                id: "PRD-005"
                description: "Artifact must be signed"
                severity: "critical"
                expr: match: {path: "artifact.signed", equals: true}
                message: "Artifact is not signed"
            },
            {
                id: "PRD-006"
                description: "Approval required"
                severity: "critical"
                expr: match: {path: "approvals", exists: true}
                message: "No approvals found"
            }
        ]
        enforcement: {
            action: "deny"
            failFast: true
        }
    }
}
