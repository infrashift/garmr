---
title: "CI/CD Pipeline Integration"
description: "Integrate Garmr into your CI/CD pipelines for automated policy enforcement"
sidebar:
  order: 3
  label: "CI/CD Integration"
---

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
# 0 = ALLOW or WARN (nothing blocked the evaluation)
# 1 = DENY (a deny-enforced policy failed)
# 2 = the evaluation did not run: server unreachable, an HTTP error,
#     unreadable input, bad flags
#
# If you need warnings to gate CI, set enforcement.action to "deny"
# in the policy — the decision belongs in code review, not a CLI flag.
```

Any nonzero code fails the job, which is the safe outcome. Branch on the
code when the pipeline should react differently: print violations on `1`,
retry or page on `2`. Every example below treats `2` as a failure, never as
a pass.

Capture the code with `rc=0; garmr eval ... || rc=$?`. That form works under
`set -e` (GitHub Actions runs `bash -e`), and avoid piping `garmr eval`
into `tee` or another command: a pipeline's status is the last command's
unless `set -o pipefail` is on, so the exit code would be lost.

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

# Parse with jq. A deny exits 1 but still prints the JSON; exit 2 prints
# nothing on stdout (the error goes to stderr).
rc=0
RESULT=$(garmr eval --input deployment.json -o json) || rc=$?
[ "$rc" -le 1 ] || { echo "evaluation failed (exit $rc)"; exit 2; }
DECISION=$(echo "$RESULT" | jq -r '.decision')
VIOLATIONS=$(echo "$RESULT" | jq '[.results[] | select(.passed == false)] | length')
```

### Namespace Filtering

```bash
# Evaluate only security policies
garmr eval --input deployment.json -n security

# Evaluate multiple namespaces (one invocation per namespace)
garmr eval --input deployment.json -n security
garmr eval --input deployment.json -n compliance
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
          # Extract the CLI from the published container image.
          docker create --name garmr-cli ghcr.io/infrashift/garmr:latest
          docker cp garmr-cli:/usr/local/bin/garmr ./garmr
          docker rm garmr-cli
          sudo mv garmr /usr/local/bin/

      - name: Evaluate Kubernetes manifests
        env:
          GARMR_SERVER: ${{ vars.GARMR_SERVER_URL }}
        run: |
          for file in k8s/*.yaml; do
            echo "Checking $file..."
            rc=0
            garmr eval --input "$file" \
              --request-id "gh-${{ github.run_id }}-${{ github.run_attempt }}" \
              -o json > result.json || rc=$?
            cat result.json

            case $rc in
              0) ;;
              1)
                echo "::error::Policy violation in $file"
                jq -r '.results[] | select(.passed == false) | "- \(.rule_id): \(.message)"' result.json
                exit 1 ;;
              *)
                echo "::error::Policy evaluation failed for $file (exit $rc)"
                exit 2 ;;
            esac
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
  # The published image's entrypoint is garmr-server; clear it so GitLab can
  # run the script. The image is Alpine without jq, so this job gates on the
  # exit code alone: 1 is a deny, 2 a failed call, and both fail the job.
  image:
    name: ghcr.io/infrashift/garmr:latest
    entrypoint: [""]
  script:
    - |
      status=0
      for file in k8s/*.yaml; do
        echo "Evaluating $file..."
        rc=0
        garmr eval --input "$file" \
          --request-id "gl-${CI_PIPELINE_ID}-${CI_JOB_ID}" \
          --server "${GARMR_SERVER_URL}" || rc=$?
        # Keep the worst code: an outage (2) outranks a deny (1).
        [ "$rc" -le "$status" ] || status=$rc
      done
      exit $status

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

                        // returnStatus keeps sh() from throwing on a nonzero
                        // exit: 1 is a deny (the JSON is still written), 2 a
                        // failed call.
                        def rc = sh(returnStatus: true, script: """
                            garmr eval --input ${file.path} \
                                --request-id "${REQUEST_ID}" \
                                --server "${GARMR_SERVER}" \
                                -o json > result.json
                        """)

                        if (rc > 1) {
                            error("Policy evaluation failed for ${file.name} (exit ${rc})")
                        }
                        if (rc == 1) {
                            def json = readJSON(file: 'result.json')
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
                docker create --name garmr-cli ghcr.io/infrashift/garmr:latest
                docker cp garmr-cli:/usr/local/bin/garmr ./garmr
                docker rm garmr-cli
                sudo mv garmr /usr/local/bin/

          - task: Bash@3
            displayName: 'Evaluate Policies'
            inputs:
              targetType: 'inline'
              script: |
                REQUEST_ID="azdo-$(Build.BuildId)-$(System.JobAttempt)"

                for file in k8s/*.yaml; do
                  echo "Checking $file..."
                  rc=0
                  garmr eval --input "$file" \
                    --request-id "$REQUEST_ID" \
                    --server "$(GARMR_SERVER)" \
                    -o json > result.json || rc=$?
                  cat result.json

                  case $rc in
                    0) ;;
                    1)
                      echo "##vso[task.logissue type=error]Policy violation in $file"
                      jq -r '.results[] | select(.passed == false) | "##vso[task.logissue type=error]\(.rule_id): \(.message)"' result.json
                      exit 1 ;;
                    *)
                      echo "##vso[task.logissue type=error]Policy evaluation failed for $file (exit $rc)"
                      exit 2 ;;
                  esac
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
            docker create --name garmr-cli ghcr.io/infrashift/garmr:latest
            docker cp garmr-cli:/usr/local/bin/garmr ./garmr
            docker rm garmr-cli
            sudo mv garmr /usr/local/bin/
      - run:
          name: Evaluate Policies
          command: |
            REQUEST_ID="circle-${CIRCLE_WORKFLOW_ID}-${CIRCLE_JOB}"

            for file in k8s/*.yaml; do
              echo "Checking $file..."
              rc=0
              garmr eval --input "$file" \
                --request-id "$REQUEST_ID" \
                --server "${GARMR_SERVER_URL}" \
                -o json > result.json || rc=$?
              cat result.json

              case $rc in
                0) ;;
                1)
                  echo "Policy violations in $file:"
                  jq -r '.results[] | select(.passed == false) | "  \(.severity) \(.rule_id): \(.message)"' result.json
                  exit 1 ;;
                *)
                  echo "Policy evaluation failed for $file (exit $rc)"
                  exit 2 ;;
              esac
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

An abridged response (the [REST API reference](/garmr/docs/guides/rest-api/#post-v1evaluate)
documents every field, including `summary` and `evaluation_mode`):

```json
{
  "decision": "deny",
  "request_id": "pipeline-12345",
  "results": [
    {
      "policy_name": "container-security",
      "policy_namespace": "security",
      "rule_id": "SEC-001",
      "description": "Containers must assert runAsNonRoot",
      "severity": "critical",
      "passed": false,
      "message": "containers must set securityContext.runAsNonRoot: true",
      "remediation": "Set securityContext.runAsNonRoot: true and specify a non-root runAsUser"
    }
  ],
  "summary": {"total_rules": 6, "passed": 5, "failed": 1, "skipped": 0},
  "metrics": {
    "evaluation_time_ns": 59524,
    "policies_evaluated": 1,
    "rules_evaluated": 6
  }
}
```

Only `200` responses carry a decision. Treat any other status — or a body
without `decision` — as a failed evaluation, never as a pass.

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

    // Anything but 200 is a failed evaluation, not an empty (passing) one.
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("garmr returned %s", resp.Status)
    }
    var result EvaluateResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    if result.Decision == "" {
        return nil, fmt.Errorf("garmr response carried no decision")
    }
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
┌─────────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  Policy Repo    │────▶│   CI Pipeline   │────▶│  Garmr Instances │
│  (Git)          │     │  (Validate)     │     │  (Reload + verify│
│                 │     │                 │     │   digest)        │
└─────────────────┘     └─────────────────┘     └──────────────────┘
        │                       │                       │
        │  1. PR with           │  2. Validate,         │  3. Deploy, reload
        │     policy change     │     test, digest      │     every instance
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

# Validate lock files in CI (directories are expanded recursively)
garmr policy validate-lock policies/

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
    outputs:
      digest: ${{ steps.digest.outputs.value }}
    steps:
      - uses: actions/checkout@v4

      - name: Install Garmr CLI
        run: |
          docker create --name garmr-cli ghcr.io/infrashift/garmr:latest
          docker cp garmr-cli:/usr/local/bin/garmr ./garmr
          docker rm garmr-cli
          sudo mv garmr /usr/local/bin/

      - name: Validate lock files
        run: garmr policy validate-lock policies/

      # garmr validate runs locally with the same loader the server uses
      # at startup — no server required. A green result means the server
      # will load the set.
      - name: Validate policies
        run: garmr validate policies/

      - name: Run policy tests
        run: garmr test policies/ --recursive --format tap

      - name: Compute expected digest
        id: digest
        run: echo "value=$(garmr policy digest policies/)" >> "$GITHUB_OUTPUT"

  deploy:
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Garmr CLI
        run: |
          docker create --name garmr-cli ghcr.io/infrashift/garmr:latest
          docker cp garmr-cli:/usr/local/bin/garmr ./garmr
          docker rm garmr-cli
          sudo mv garmr /usr/local/bin/

      # Land the files on the volume the server's --policy-dir points at.
      # How depends on your platform: a Nomad artifact stanza fetching the
      # git ref, an init container syncing object storage, a CSI/host
      # volume writer, or a ConfigMap rollout on Kubernetes.

      # Then reload EVERY instance and require the digest CI computed. One
      # POST /v1/policies/reload reaches one instance only; behind a load
      # balancer it would pass while the rest of the fleet stays stale.
      # The command exits 1 if any instance fails to reload (a broken tree
      # returns 500 and keeps the old set serving), reports a different
      # digest, or the instances diverge.
      - name: Reload and verify convergence
        env:
          # Comma-separated instance URLs, e.g.
          # http://10.0.0.11:8080,http://10.0.0.12:8080
          GARMR_INSTANCES: ${{ vars.GARMR_INSTANCES }}
        run: |
          garmr policy reload \
            --servers "$GARMR_INSTANCES" \
            --expect-digest "${{ needs.validate.outputs.digest }}"
```

If the instances sit behind a single load-balancing address you can't
bypass (a mesh upstream), use
`garmr policy reload --server <addr> --converge --instances <N> --expect-digest <digest>`
instead, run from somewhere that can reach that address. On Nomad with
Consul Connect, CI dispatches the in-mesh reload job, which does exactly
this: `nomad job dispatch -meta digest="$DIGEST" garmr-reload` (see
[Deploying Garmr](/garmr/docs/operations/deploying/#updating-policies)).
Restarting or rolling the instances also works: each one loads at startup
and fails closed on a bad set.

### Rollback Strategy

```bash
# Tag releases
git tag -a policy-v1.2.0 -m "Policy release 1.2.0"
git push origin policy-v1.2.0

# Rollback = deploy the previous ref through the same pipeline: check out
# the tag, land the files on the policy volume, restart or reload, then
# verify the digest matches the rolled-back checkout.
git checkout policy-v1.1.0 -- policies/
garmr policy digest policies/   # expected digest after the rollback
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

`garmr eval` exits `1` for a deny and `2` when the evaluation did not run.
Branch on the code; keep stderr separate so an error message never lands
in the JSON:

```bash
rc=0
RESULT=$(garmr eval --input resource.json -o json 2>eval.err) || rc=$?

case $rc in
  0)
    echo "Policy check passed ($(echo "$RESULT" | jq -r .decision))" ;;
  1)
    echo "Policy violation detected"
    echo "$RESULT" | jq '.results[] | select(.passed == false)'
    exit 1 ;;
  *)
    echo "Policy evaluation failed:"; cat eval.err
    exit 2 ;;
esac
```

### Retry Logic

Retry only exit `2`. A deny (`1`) is a verdict, and evaluating the same
input again returns the same deny:

```bash
MAX_RETRIES=3
RETRY_DELAY=5

for i in $(seq 1 $MAX_RETRIES); do
    rc=0
    garmr eval --input resource.json || rc=$?
    [ "$rc" -eq 2 ] || break   # a verdict (0 allow/warn, 1 deny): stop retrying

    if [ $i -eq $MAX_RETRIES ]; then
        echo "Evaluation failed after $MAX_RETRIES attempts"
        exit 2
    fi

    echo "Retry $i/$MAX_RETRIES in ${RETRY_DELAY}s..."
    sleep $RETRY_DELAY
done

[ "$rc" -eq 0 ] || { echo "Policy violation"; exit 1; }
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

# Check audit log (file mode; with audit.path: stdout, search the platform's
# log pipeline instead, e.g. `nomad alloc logs <alloc>`)
tail -f /var/log/garmr/audit.log | jq 'select(.request_id == "test-123")'
```

**Reload succeeded but a server still serves old policies**

A reload call reaches one instance. Compare each instance's digest with the
checkout's:

```bash
garmr policy digest policies/
for s in http://10.0.0.11:8080 http://10.0.0.12:8080; do
  curl -s "$s/v1/policies" | jq -r '"\(.instance_id) \(.digest)"'
done
```

Then reload them all with `garmr policy reload --servers ... --expect-digest ...`.
