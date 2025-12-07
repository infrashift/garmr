package test

simpleTest: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "simple-test"
        namespace: "test"
    }
    spec: {
        description: "Simple test policy"
        target: resources: ["test"]
        rules: [
            {
                id: "TEST-001"
                description: "Test field exists"
                severity: "medium"
                expr: {match: {path: "test", exists: true}}
                message: "The 'test' field does not exist"
            },
            {
                id: "TEST-002"
                description: "Test field is true"
                severity: "medium"
                expr: {match: {path: "test", equals: true}}
                message: "The 'test' field is not true"
            }
        ]
        enforcement: action: "warn"
    }
}

numericTest: {
    apiVersion: "policy.q.io/v1"
    kind: "Policy"
    metadata: {
        name: "numeric-test"
        namespace: "test"
    }
    spec: {
        description: "Numeric comparison test policy"
        target: resources: ["test"]
        rules: [
            {
                id: "NUM-001"
                description: "Count must be positive"
                severity: "high"
                expr: {match: {path: "count", greaterThan: 0}}
                message: "Count must be greater than 0"
            },
            {
                id: "NUM-002"
                description: "Score must be at least 50"
                severity: "medium"
                expr: {match: {path: "score", greaterThanOrEqual: 50}}
                message: "Score is below 50"
            }
        ]
        enforcement: action: "deny"
    }
}
