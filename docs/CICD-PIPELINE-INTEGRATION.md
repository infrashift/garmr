# CI/CD Pipeline Integration

This guide describes how to integrate Garmr into your CI/CD pipelines for automated policy enforcement.

## Overview

Garmr can be integrated into your pipelines in two ways:

1. **CLI (`garmr eval`)** - Recommended for most use cases
2. **REST API** - For advanced integrations or non-shell environments

Both methods support request ID correlation for audit trail tracking.

---

## CLI Integration

### Basic Usage

```bash
# Evaluate a resource
garmr eval --input deployment.json

# Exit codes:
# 0 = ALLOW (all policies passed)
# 1 = DENY (one or more policies failed)
# 2 = WARN (warnings, with --fail-on-warn)
```

### Request ID for Audit Correlation

Always pass a request ID to correlate pipeline runs with audit logs:

```bash
# Use your CI system's job/run ID
garmr eval --input deployment.json --request-id "${CI_JOB_ID}"
```

### JSON Output for Parsing

```bash
# Machine-readable output
garmr eval --input deployment.json -o json

# Parse with jq
RESULT=$(garmr eval --input deployment.json -o json)
DECISION=$(echo "$RESULT" | jq -r '.decision')
VIOLATIONS=$(echo "$RESULT" | jq -r '.results | length')
```

### Namespace Filtering

```bash
# Evaluate only security policies
garmr eval --input deployment.json -n security

# Evaluate multiple namespaces
garmr eval --input deployment.json -n security -n compliance
```

---

## Pipeline Examples

### GitHub Actions

```yaml
name: Policy Check
on:
  pull_request:
    paths:
      - 'k8s/**'

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Garmr CLI
        run: |
          curl -sL https://github.com/infrashift/garmr/releases/latest/download/garmr-linux-amd64 -o garmr
          chmod +x garmr
          sudo mv garmr /usr/local/bin/
      
      - name: Evaluate Kubernetes manifests
        env:
          GARMR_SERVER: ${{ vars.GARMR_SERVER_URL }}
        run: |
          for file in k8s/*.yaml; do
            echo "Checking $file..."
            garmr eval --input "$file" \
              --request-id "gh-${{ github.run_id }}-${{ github.run_attempt }}" \
              -o json | tee result.json
            
            if [ "$(jq -r '.decision' result.json)" = "deny" ]; then
              echo "::error::Policy violation in $file"
              jq -r '.results[] | select(.passed == false) | "- \(.rule_id): \(.message)"' result.json
              exit 1
            fi
          done

      - name: Upload policy results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: policy-results
          path: result.json
```

### GitLab CI

```yaml
stages:
  - validate
  - deploy

policy-check:
  stage: validate
  image: infrashift/garmr:latest
  script:
    - |
      for file in k8s/*.yaml; do
        echo "Evaluating $file..."
        garmr eval --input "$file" \
          --request-id "gl-${CI_PIPELINE_ID}-${CI_JOB_ID}" \
          --server "${GARMR_SERVER_URL}" \
          -o json > result.json
        
        DECISION=$(jq -r '.decision' result.json)
        if [ "$DECISION" = "deny" ]; then
          echo "Policy violations found:"
          jq -r '.results[] | select(.passed == false) | "\(.severity): \(.rule_id) - \(.message)"' result.json
          exit 1
        fi
      done
  artifacts:
    reports:
      dotenv: policy-results.env
    paths:
      - result.json
    when: always

deploy:
  stage: deploy
  needs: [policy-check]
  script:
    - kubectl apply -f k8s/
```

### Jenkins

```groovy
pipeline {
    agent any
    
    environment {
        GARMR_SERVER = credentials('garmr-server-url')
        REQUEST_ID = "jenkins-${BUILD_NUMBER}-${JOB_NAME}"
    }
    
    stages {
        stage('Policy Check') {
            steps {
                script {
                    def files = findFiles(glob: 'k8s/*.yaml')
                    def failed = false
                    
                    files.each { file ->
                        echo "Evaluating ${file.name}..."
                        
                        def result = sh(
                            script: """
                                garmr eval --input ${file.path} \
                                    --request-id "${REQUEST_ID}" \
                                    --server "${GARMR_SERVER}" \
                                    -o json
                            """,
                            returnStdout: true
                        ).trim()
                        
                        def json = readJSON(text: result)
                        
                        if (json.decision == 'deny') {
                            failed = true
                            echo "POLICY VIOLATION in ${file.name}"
                            json.results.findAll { !it.passed }.each { r ->
                                echo "  - ${r.rule_id}: ${r.message}"
                            }
                        }
                    }
                    
                    if (failed) {
                        error("Policy violations detected")
                    }
                }
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'kubectl apply -f k8s/'
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'result.json', allowEmptyArchive: true
        }
    }
}
```

### Azure DevOps

```yaml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - k8s/*

pool:
  vmImage: 'ubuntu-latest'

variables:
  GARMR_SERVER: $(QServerUrl)

stages:
  - stage: Validate
    jobs:
      - job: PolicyCheck
        steps:
          - task: Bash@3
            displayName: 'Install Garmr CLI'
            inputs:
              targetType: 'inline'
              script: |
                curl -sL https://github.com/infrashift/garmr/releases/latest/download/garmr-linux-amd64 -o garmr
                chmod +x garmr
                sudo mv garmr /usr/local/bin/

          - task: Bash@3
            displayName: 'Evaluate Policies'
            inputs:
              targetType: 'inline'
              script: |
                REQUEST_ID="azdo-$(Build.BuildId)-$(System.JobAttempt)"
                
                for file in k8s/*.yaml; do
                  echo "Checking $file..."
                  garmr eval --input "$file" \
                    --request-id "$REQUEST_ID" \
                    --server "$(GARMR_SERVER)" \
                    -o json | tee result.json
                  
                  DECISION=$(jq -r '.decision' result.json)
                  if [ "$DECISION" = "deny" ]; then
                    echo "##vso[task.logissue type=error]Policy violation in $file"
                    jq -r '.results[] | select(.passed == false) | "##vso[task.logissue type=error]\(.rule_id): \(.message)"' result.json
                    exit 1
                  fi
                done

          - task: PublishBuildArtifacts@1
            condition: always()
            inputs:
              pathToPublish: 'result.json'
              artifactName: 'policy-results'
```

### CircleCI

```yaml
version: 2.1

jobs:
  policy-check:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install Garmr CLI
          command: |
            curl -sL https://github.com/infrashift/garmr/releases/latest/download/garmr-linux-amd64 -o garmr
            chmod +x garmr
            sudo mv garmr /usr/local/bin/
      - run:
          name: Evaluate Policies
          command: |
            REQUEST_ID="circle-${CIRCLE_WORKFLOW_ID}-${CIRCLE_JOB}"
            
            for file in k8s/*.yaml; do
              echo "Checking $file..."
              garmr eval --input "$file" \
                --request-id "$REQUEST_ID" \
                --server "${GARMR_SERVER_URL}" \
                -o json | tee result.json
              
              if [ "$(jq -r '.decision' result.json)" = "deny" ]; then
                echo "Policy violations in $file:"
                jq -r '.results[] | select(.passed == false) | "  \(.severity) \(.rule_id): \(.message)"' result.json
                exit 1
              fi
            done
      - store_artifacts:
          path: result.json
          destination: policy-results

workflows:
  version: 2
  build-and-deploy:
    jobs:
      - policy-check
      - deploy:
          requires:
            - policy-check
          filters:
            branches:
              only: main
```

---

## REST API Integration

For environments where the CLI isn't available, use the REST API directly.

### Basic Request

```bash
curl -X POST http://garmr-server:8080/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Request-Id: pipeline-12345" \
  -d @- << 'EOF'
{
  "input": {
    "kind": "Deployment",
    "metadata": {
      "name": "my-app",
      "namespace": "production"
    },
    "spec": {
      "replicas": 3
    }
  },
  "namespace": "security"
}
EOF
```

### Response Format

```json
{
  "decision": "deny",
  "request_id": "pipeline-12345",
  "results": [
    {
      "policy_name": "container-security",
      "policy_namespace": "security",
      "rule_id": "SEC-001",
      "description": "Containers must not run as root",
      "severity": "high",
      "passed": false,
      "message": "Container is running as root"
    }
  ],
  "metrics": {
    "evaluation_time_ns": 1234567,
    "policies_evaluated": 2,
    "rules_evaluated": 8
  }
}
```

### Python Example

```python
import requests
import os
import sys
import json

GARMR_SERVER = os.environ.get('GARMR_SERVER', 'http://localhost:8080')
REQUEST_ID = os.environ.get('CI_JOB_ID', 'local-test')

def evaluate_resource(resource_path: str, namespace: str = None) -> dict:
    with open(resource_path) as f:
        resource = json.load(f)
    
    payload = {
        'input': resource,
        'namespace': namespace
    }
    
    headers = {
        'Content-Type': 'application/json',
        'X-Request-Id': REQUEST_ID
    }
    
    response = requests.post(
        f'{GARMR_SERVER}/v1/evaluate',
        json=payload,
        headers=headers
    )
    response.raise_for_status()
    return response.json()

def main():
    result = evaluate_resource('deployment.json', namespace='security')
    
    print(f"Decision: {result['decision']}")
    print(f"Request ID: {result['request_id']}")
    
    if result['decision'] == 'deny':
        print("\nViolations:")
        for r in result['results']:
            if not r['passed']:
                print(f"  - [{r['severity']}] {r['rule_id']}: {r['message']}")
        sys.exit(1)
    
    print("All policies passed!")
    sys.exit(0)

if __name__ == '__main__':
    main()
```

### Go Example

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
)

type EvaluateRequest struct {
    Input     map[string]interface{} `json:"input"`
    Namespace string                 `json:"namespace,omitempty"`
}

type EvaluateResponse struct {
    Decision  string       `json:"decision"`
    RequestID string       `json:"request_id"`
    Results   []RuleResult `json:"results"`
}

type RuleResult struct {
    RuleID   string `json:"rule_id"`
    Passed   bool   `json:"passed"`
    Message  string `json:"message"`
    Severity string `json:"severity"`
}

func evaluate(server, requestID string, input map[string]interface{}) (*EvaluateResponse, error) {
    payload, _ := json.Marshal(EvaluateRequest{Input: input})
    
    req, _ := http.NewRequest("POST", server+"/v1/evaluate", bytes.NewReader(payload))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Request-Id", requestID)
    
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result EvaluateResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}

func main() {
    server := os.Getenv("GARMR_SERVER")
    requestID := os.Getenv("CI_JOB_ID")
    
    input := map[string]interface{}{
        "kind": "Deployment",
        "metadata": map[string]interface{}{
            "name": "my-app",
        },
    }
    
    result, err := evaluate(server, requestID, input)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    
    if result.Decision == "deny" {
        fmt.Println("Policy violations:")
        for _, r := range result.Results {
            if !r.Passed {
                fmt.Printf("  - %s: %s\n", r.RuleID, r.Message)
            }
        }
        os.Exit(1)
    }
    
    fmt.Println("All policies passed!")
}
```

---

## Version-Controlled Policy Deployment

### Workflow Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Policy Repo    │────▶│   CI Pipeline   │────▶│  Garmr Server   │
│  (Git)          │     │  (Validate)     │     │  (Hot Reload)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │  1. PR with           │  2. Validate          │  3. Deploy
        │     policy change     │     policies          │     & reload
        ▼                       ▼                       ▼
```

### Git Repository Structure

```
policies/
├── security/
│   ├── container-security.cue
│   ├── container-security.cue.lock
│   ├── network-policy.cue
│   └── network-policy.cue.lock
├── compliance/
│   ├── pci-dss.cue
│   └── pci-dss.cue.lock
├── release/
│   ├── prod-gate.cue
│   └── prod-gate.cue.lock
└── README.md
```

### Lock File Generation

Generate lock files for change tracking:

```bash
# Generate lock file for a policy
garmr policy lock policies/security/container-security.cue --version 1.0.0

# Validate lock files in CI
garmr policy validate-lock --recursive policies/

# Check diff
garmr policy diff policies/security/container-security.cue
```

### CI Pipeline for Policy Changes

```yaml
name: Policy Deployment
on:
  push:
    branches: [main]
    paths:
      - 'policies/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Validate lock files
        run: garmr policy validate-lock --recursive policies/
      
      - name: Validate policy syntax
        run: |
          for file in $(find policies -name "*.cue" ! -name "*.lock"); do
            garmr validate "$file"
          done

  deploy:
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Deploy policies
        run: |
          rsync -av policies/ ${{ secrets.GARMR_SERVER }}:/etc/garmr/policies/
      
      - name: Trigger reload
        run: |
          curl -X POST https://${{ secrets.GARMR_SERVER }}/v1/policies/reload \
            -H "Authorization: Bearer ${{ secrets.GARMR_API_TOKEN }}"
      
      - name: Verify deployment
        run: |
          # List policies and verify count
          POLICY_COUNT=$(curl -s https://${{ secrets.GARMR_SERVER }}/v1/policies | jq '.policies | length')
          echo "Deployed $POLICY_COUNT policies"
```

### Rollback Strategy

```bash
# Tag releases
git tag -a policy-v1.2.0 -m "Policy release 1.2.0"
git push origin policy-v1.2.0

# Rollback to previous version
git checkout policy-v1.1.0 -- policies/
rsync -av policies/ server:/etc/garmr/policies/
curl -X POST https://garmr-server/v1/policies/reload
```

---

## Best Practices

### Request ID Conventions

Use consistent, meaningful request IDs:

| CI System | Pattern | Example |
|-----------|---------|---------|
| GitHub Actions | `gh-{run_id}-{attempt}` | `gh-12345-1` |
| GitLab CI | `gl-{pipeline_id}-{job_id}` | `gl-98765-54321` |
| Jenkins | `jenkins-{build_number}` | `jenkins-456` |
| Azure DevOps | `azdo-{build_id}-{attempt}` | `azdo-789-1` |
| CircleCI | `circle-{workflow_id}` | `circle-abc123` |

### Error Handling

```bash
# Capture both stdout and exit code
set +e
RESULT=$(garmr eval --input resource.json -o json 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 1 ]; then
    echo "Policy violation detected"
    echo "$RESULT" | jq '.results[] | select(.passed == false)'
    # Optionally fail or continue based on severity
fi
```

### Timeout Configuration

```bash
# Set evaluation timeout
garmr eval --input resource.json --timeout 30s

# Or via environment
export GARMR_TIMEOUT=30s
garmr eval --input resource.json
```

### Retry Logic

```bash
MAX_RETRIES=3
RETRY_DELAY=5

for i in $(seq 1 $MAX_RETRIES); do
    if garmr eval --input resource.json -o json; then
        break
    fi
    
    if [ $i -eq $MAX_RETRIES ]; then
        echo "Failed after $MAX_RETRIES attempts"
        exit 1
    fi
    
    echo "Retry $i/$MAX_RETRIES in ${RETRY_DELAY}s..."
    sleep $RETRY_DELAY
done
```

---

## Troubleshooting

### Common Issues

**Connection refused**
```bash
# Check server is running
curl http://garmr-server:8080/health

# Check network connectivity
nc -zv garmr-server 8080
```

**Policy not found**
```bash
# List available policies
garmr policy list

# Check namespace
garmr policy list -n security
```

**Request ID not in audit log**
```bash
# Verify header is being sent
curl -v -X POST http://garmr-server:8080/v1/evaluate \
  -H "X-Request-Id: test-123" \
  -H "Content-Type: application/json" \
  -d '{"input": {}}'

# Check audit log
tail -f /var/log/garmr/audit.log | jq 'select(.request_id == "test-123")'
```