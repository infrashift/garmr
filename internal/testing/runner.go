// internal/testing/runner.go
// Package testing provides policy testing capabilities for Garmr.
package testing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
)

// TestSuite represents a collection of policy tests.
type TestSuite struct {
	// Policy is the name of the policy being tested
	Policy string `json:"policy"`

	// Source is the path to the test file
	Source string `json:"source,omitempty"`

	// Tests are the individual test cases
	Tests []TestCase `json:"tests"`
}

// TestCase represents a single policy test.
type TestCase struct {
	// Name of the test case
	Name string `json:"name"`

	// Description of what the test validates
	Description string `json:"description,omitempty"`

	// Skip this test
	Skip bool `json:"skip,omitempty"`

	// SkipReason explains why the test is skipped
	SkipReason string `json:"skipReason,omitempty"`

	// Input is the test input data
	Input map[string]interface{} `json:"input"`

	// Context provides additional context (environment, principal, etc.)
	Context map[string]interface{} `json:"context,omitempty"`

	// Expect defines expected outcomes
	Expect TestExpectation `json:"expect"`
}

// TestExpectation defines what the test expects.
type TestExpectation struct {
	// Decision: allow, deny, or "" (don't check)
	Decision string `json:"decision,omitempty"`

	// Violations expected
	Violations []ExpectedViolation `json:"violations,omitempty"`

	// NoViolations expects no violations
	NoViolations bool `json:"noViolations,omitempty"`

	// ViolationCount is the expected number of violations
	ViolationCount *int `json:"violationCount,omitempty"`

	// Output is expected output data (for data policies)
	Output map[string]interface{} `json:"output,omitempty"`

	// Error expects an error
	Error bool `json:"error,omitempty"`

	// ErrorContains checks error message
	ErrorContains string `json:"errorContains,omitempty"`
}

// ExpectedViolation defines an expected violation.
type ExpectedViolation struct {
	// ID of the rule that should trigger
	ID string `json:"id"`

	// Severity expected (optional)
	Severity string `json:"severity,omitempty"`

	// MessageContains checks violation message (optional)
	MessageContains string `json:"messageContains,omitempty"`
}

// TestResult represents the result of running a test.
type TestResult struct {
	// Name of the test
	Name string `json:"name"`

	// Passed indicates if the test passed
	Passed bool `json:"passed"`

	// Skipped indicates if the test was skipped
	Skipped bool `json:"skipped"`

	// SkipReason if skipped
	SkipReason string `json:"skipReason,omitempty"`

	// Duration of the test
	Duration time.Duration `json:"duration"`

	// Failures are the reasons the test failed
	Failures []string `json:"failures,omitempty"`

	// Actual is the actual result (for debugging)
	Actual *ActualResult `json:"actual,omitempty"`
}

// ActualResult contains the actual evaluation result.
type ActualResult struct {
	Decision   string      `json:"decision"`
	Violations []Violation `json:"violations,omitempty"`
	Output     interface{} `json:"output,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// Violation represents a policy violation.
type Violation struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// SuiteResult contains results for a test suite.
type SuiteResult struct {
	Policy   string        `json:"policy"`
	Source   string        `json:"source"`
	Total    int           `json:"total"`
	Passed   int           `json:"passed"`
	Failed   int           `json:"failed"`
	Skipped  int           `json:"skipped"`
	Duration time.Duration `json:"duration"`
	Results  []TestResult  `json:"results"`
}

// Runner executes policy tests.
type Runner struct {
	ctx      *cue.Context
	policies map[string]cue.Value
	verbose  bool
}

// NewRunner creates a new test runner.
func NewRunner(verbose bool) *Runner {
	return &Runner{
		ctx:      cuecontext.New(),
		policies: make(map[string]cue.Value),
		verbose:  verbose,
	}
}

// LoadPolicy loads a policy for testing.
func (r *Runner) LoadPolicy(name string, source string) error {
	value := r.ctx.CompileString(source, cue.Filename(name+".cue"))
	if value.Err() != nil {
		return fmt.Errorf("compiling policy: %w", value.Err())
	}
	r.policies[name] = value
	return nil
}

// LoadPolicyFile loads a policy from a file.
func (r *Runner) LoadPolicyFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return r.LoadPolicy(name, string(content))
}

// LoadTestSuite loads a test suite from CUE source.
func (r *Runner) LoadTestSuite(source string) (*TestSuite, error) {
	value := r.ctx.CompileString(source)
	if value.Err() != nil {
		return nil, fmt.Errorf("compiling test suite: %w", value.Err())
	}

	suite := &TestSuite{}

	// Extract policy name
	if p := value.LookupPath(cue.ParsePath("policy")); p.Exists() {
		suite.Policy, _ = p.String()
	}

	// Extract tests
	if tests := value.LookupPath(cue.ParsePath("tests")); tests.Exists() {
		iter, _ := tests.List()
		for iter.Next() {
			tc, err := r.parseTestCase(iter.Value())
			if err != nil {
				return nil, fmt.Errorf("parsing test case: %w", err)
			}
			suite.Tests = append(suite.Tests, tc)
		}
	}

	return suite, nil
}

// LoadTestSuiteFile loads a test suite from a file.
func (r *Runner) LoadTestSuiteFile(path string) (*TestSuite, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	suite, err := r.LoadTestSuite(string(content))
	if err != nil {
		return nil, err
	}
	suite.Source = path

	return suite, nil
}

func (r *Runner) parseTestCase(value cue.Value) (TestCase, error) {
	tc := TestCase{}

	if v := value.LookupPath(cue.ParsePath("name")); v.Exists() {
		tc.Name, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("description")); v.Exists() {
		tc.Description, _ = v.String()
	}
	if v := value.LookupPath(cue.ParsePath("skip")); v.Exists() {
		tc.Skip, _ = v.Bool()
	}
	if v := value.LookupPath(cue.ParsePath("skipReason")); v.Exists() {
		tc.SkipReason, _ = v.String()
	}

	// Parse input
	if v := value.LookupPath(cue.ParsePath("input")); v.Exists() {
		inputJSON, _ := v.MarshalJSON()
		json.Unmarshal(inputJSON, &tc.Input)
	}

	// Parse context
	if v := value.LookupPath(cue.ParsePath("context")); v.Exists() {
		ctxJSON, _ := v.MarshalJSON()
		json.Unmarshal(ctxJSON, &tc.Context)
	}

	// Parse expectations
	if expect := value.LookupPath(cue.ParsePath("expect")); expect.Exists() {
		if v := expect.LookupPath(cue.ParsePath("decision")); v.Exists() {
			tc.Expect.Decision, _ = v.String()
		}
		if v := expect.LookupPath(cue.ParsePath("noViolations")); v.Exists() {
			tc.Expect.NoViolations, _ = v.Bool()
		}
		if v := expect.LookupPath(cue.ParsePath("violationCount")); v.Exists() {
			count, _ := v.Int64()
			countInt := int(count)
			tc.Expect.ViolationCount = &countInt
		}
		if v := expect.LookupPath(cue.ParsePath("error")); v.Exists() {
			tc.Expect.Error, _ = v.Bool()
		}
		if v := expect.LookupPath(cue.ParsePath("errorContains")); v.Exists() {
			tc.Expect.ErrorContains, _ = v.String()
		}

		// Parse expected violations
		if violations := expect.LookupPath(cue.ParsePath("violations")); violations.Exists() {
			iter, _ := violations.List()
			for iter.Next() {
				ev := ExpectedViolation{}
				if v := iter.Value().LookupPath(cue.ParsePath("id")); v.Exists() {
					ev.ID, _ = v.String()
				}
				if v := iter.Value().LookupPath(cue.ParsePath("severity")); v.Exists() {
					ev.Severity, _ = v.String()
				}
				if v := iter.Value().LookupPath(cue.ParsePath("messageContains")); v.Exists() {
					ev.MessageContains, _ = v.String()
				}
				tc.Expect.Violations = append(tc.Expect.Violations, ev)
			}
		}
	}

	return tc, nil
}

// RunSuite runs all tests in a suite.
func (r *Runner) RunSuite(ctx context.Context, suite *TestSuite) *SuiteResult {
	start := time.Now()

	result := &SuiteResult{
		Policy:  suite.Policy,
		Source:  suite.Source,
		Total:   len(suite.Tests),
		Results: make([]TestResult, 0, len(suite.Tests)),
	}

	for _, tc := range suite.Tests {
		tr := r.RunTest(ctx, suite.Policy, tc)
		result.Results = append(result.Results, tr)

		if tr.Skipped {
			result.Skipped++
		} else if tr.Passed {
			result.Passed++
		} else {
			result.Failed++
		}
	}

	result.Duration = time.Since(start)
	return result
}

// RunTest runs a single test case.
func (r *Runner) RunTest(ctx context.Context, policyName string, tc TestCase) TestResult {
	start := time.Now()

	result := TestResult{
		Name: tc.Name,
	}

	// Handle skipped tests
	if tc.Skip {
		result.Skipped = true
		result.SkipReason = tc.SkipReason
		result.Duration = time.Since(start)
		return result
	}

	// Get policy
	policy, exists := r.policies[policyName]
	if !exists {
		result.Passed = false
		result.Failures = append(result.Failures, fmt.Sprintf("policy not loaded: %s", policyName))
		result.Duration = time.Since(start)
		return result
	}

	// Evaluate policy
	actual, evalErr := r.evaluate(ctx, policy, tc.Input, tc.Context)
	result.Actual = actual

	// Check expectations
	var failures []string

	// Check for expected error
	if tc.Expect.Error {
		if actual.Error == "" {
			failures = append(failures, "expected error but got none")
		} else if tc.Expect.ErrorContains != "" && !strings.Contains(actual.Error, tc.Expect.ErrorContains) {
			failures = append(failures, fmt.Sprintf("error should contain %q, got %q", tc.Expect.ErrorContains, actual.Error))
		}
	} else if evalErr != nil {
		failures = append(failures, fmt.Sprintf("unexpected error: %v", evalErr))
	}

	// Check decision
	if tc.Expect.Decision != "" && actual.Decision != tc.Expect.Decision {
		failures = append(failures, fmt.Sprintf("expected decision %q, got %q", tc.Expect.Decision, actual.Decision))
	}

	// Check violations
	if tc.Expect.NoViolations && len(actual.Violations) > 0 {
		failures = append(failures, fmt.Sprintf("expected no violations, got %d", len(actual.Violations)))
	}

	if tc.Expect.ViolationCount != nil && len(actual.Violations) != *tc.Expect.ViolationCount {
		failures = append(failures, fmt.Sprintf("expected %d violations, got %d", *tc.Expect.ViolationCount, len(actual.Violations)))
	}

	// Check specific violations
	for _, ev := range tc.Expect.Violations {
		found := false
		for _, av := range actual.Violations {
			if av.ID == ev.ID {
				found = true
				if ev.Severity != "" && av.Severity != ev.Severity {
					failures = append(failures, fmt.Sprintf("violation %s: expected severity %q, got %q", ev.ID, ev.Severity, av.Severity))
				}
				if ev.MessageContains != "" && !strings.Contains(av.Message, ev.MessageContains) {
					failures = append(failures, fmt.Sprintf("violation %s: message should contain %q", ev.ID, ev.MessageContains))
				}
				break
			}
		}
		if !found {
			failures = append(failures, fmt.Sprintf("expected violation %s not found", ev.ID))
		}
	}

	result.Failures = failures
	result.Passed = len(failures) == 0
	result.Duration = time.Since(start)

	return result
}

func (r *Runner) evaluate(ctx context.Context, policy cue.Value, input map[string]interface{}, evalCtx map[string]interface{}) (*ActualResult, error) {
	result := &ActualResult{
		Decision: "allow", // Default
	}

	// Encode input
	inputValue := r.ctx.Encode(input)
	if inputValue.Err() != nil {
		result.Error = inputValue.Err().Error()
		return result, inputValue.Err()
	}

	// Unify with policy
	unified := policy.FillPath(cue.ParsePath("input"), inputValue)
	if unified.Err() != nil {
		result.Error = unified.Err().Error()
		return result, nil // Not an error for testing purposes
	}

	// Extract decision
	if decision := unified.LookupPath(cue.ParsePath("decision")); decision.Exists() {
		result.Decision, _ = decision.String()
	}

	// Extract violations
	if violations := unified.LookupPath(cue.ParsePath("violations")); violations.Exists() {
		iter, _ := violations.List()
		for iter.Next() {
			v := Violation{}
			if id := iter.Value().LookupPath(cue.ParsePath("id")); id.Exists() {
				v.ID, _ = id.String()
			}
			if sev := iter.Value().LookupPath(cue.ParsePath("severity")); sev.Exists() {
				v.Severity, _ = sev.String()
			}
			if msg := iter.Value().LookupPath(cue.ParsePath("message")); msg.Exists() {
				v.Message, _ = msg.String()
			}
			result.Violations = append(result.Violations, v)
		}
	}

	// Infer decision from violations if not explicit
	if result.Decision == "allow" && len(result.Violations) > 0 {
		result.Decision = "deny"
	}

	return result, nil
}

// FormatResults formats test results for display.
func FormatResults(result *SuiteResult, verbose bool) string {
	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf("\n=== Testing %s ===\n", result.Policy))
	if result.Source != "" {
		sb.WriteString(fmt.Sprintf("Source: %s\n", result.Source))
	}
	sb.WriteString("\n")

	// Individual results
	for _, tr := range result.Results {
		if tr.Skipped {
			sb.WriteString(fmt.Sprintf("  ⏭  %s (skipped", tr.Name))
			if tr.SkipReason != "" {
				sb.WriteString(fmt.Sprintf(": %s", tr.SkipReason))
			}
			sb.WriteString(")\n")
		} else if tr.Passed {
			sb.WriteString(fmt.Sprintf("  ✓  %s (%s)\n", tr.Name, tr.Duration))
		} else {
			sb.WriteString(fmt.Sprintf("  ✗  %s (%s)\n", tr.Name, tr.Duration))
			for _, f := range tr.Failures {
				sb.WriteString(fmt.Sprintf("      → %s\n", f))
			}
			if verbose && tr.Actual != nil {
				sb.WriteString(fmt.Sprintf("      Actual: decision=%s, violations=%d\n",
					tr.Actual.Decision, len(tr.Actual.Violations)))
			}
		}
	}

	// Summary
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Results: %d passed, %d failed, %d skipped (total: %d)\n",
		result.Passed, result.Failed, result.Skipped, result.Total))
	sb.WriteString(fmt.Sprintf("Duration: %s\n", result.Duration))

	if result.Failed > 0 {
		sb.WriteString("\n❌ FAILED\n")
	} else {
		sb.WriteString("\n✅ PASSED\n")
	}

	return sb.String()
}
