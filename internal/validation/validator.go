// internal/validation/validator.go
// Package validation provides input validation for policy evaluation.
package validation

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
)

// Validator validates inputs against a schema.
type Validator struct {
	ctx     *cue.Context
	schemas map[string]cue.Value // policy -> schema
}

// ValidationError represents a validation failure.
type ValidationError struct {
	Field    string `json:"field"`
	Message  string `json:"message"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Code     string `json:"code"`
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// ValidationResult contains the result of input validation.
type ValidationResult struct {
	Valid  bool               `json:"valid"`
	Errors []*ValidationError `json:"errors,omitempty"`
}

// NewValidator creates a new input validator.
func NewValidator() *Validator {
	return &Validator{
		ctx:     cuecontext.New(),
		schemas: make(map[string]cue.Value),
	}
}

// RegisterSchema registers an input schema for a policy.
func (v *Validator) RegisterSchema(policyName string, schema cue.Value) {
	v.schemas[policyName] = schema
}

// RegisterSchemaFromCUE registers a schema from CUE source.
func (v *Validator) RegisterSchemaFromCUE(policyName, schemaSource string) error {
	value := v.ctx.CompileString(schemaSource)
	if value.Err() != nil {
		return fmt.Errorf("compiling schema: %w", value.Err())
	}
	v.schemas[policyName] = value
	return nil
}

// ExtractSchemaFromPolicy extracts the inputSchema from a policy value.
func (v *Validator) ExtractSchemaFromPolicy(policyName string, policy cue.Value) error {
	schema := policy.LookupPath(cue.ParsePath("spec.inputSchema"))
	if !schema.Exists() {
		// No schema defined, validation will pass
		return nil
	}
	v.schemas[policyName] = schema
	return nil
}

// Validate validates input against the registered schema.
func (v *Validator) Validate(policyName string, input interface{}) *ValidationResult {
	schema, exists := v.schemas[policyName]
	if !exists {
		// No schema registered, validation passes
		return &ValidationResult{Valid: true}
	}

	// Convert input to CUE value
	inputValue := v.ctx.Encode(input)
	if inputValue.Err() != nil {
		return &ValidationResult{
			Valid: false,
			Errors: []*ValidationError{{
				Code:    "ENCODE_ERROR",
				Message: fmt.Sprintf("failed to encode input: %v", inputValue.Err()),
			}},
		}
	}

	// Unify input with schema
	unified := schema.Unify(inputValue)
	if unified.Err() != nil {
		errors := v.extractErrors(unified.Err())
		return &ValidationResult{
			Valid:  false,
			Errors: errors,
		}
	}

	// Validate the unified value
	if err := unified.Validate(cue.Concrete(true)); err != nil {
		errors := v.extractErrors(err)
		return &ValidationResult{
			Valid:  false,
			Errors: errors,
		}
	}

	return &ValidationResult{Valid: true}
}

// ValidateWithSchema validates input against an inline schema.
func (v *Validator) ValidateWithSchema(schema cue.Value, input interface{}) *ValidationResult {
	inputValue := v.ctx.Encode(input)
	if inputValue.Err() != nil {
		return &ValidationResult{
			Valid: false,
			Errors: []*ValidationError{{
				Code:    "ENCODE_ERROR",
				Message: fmt.Sprintf("failed to encode input: %v", inputValue.Err()),
			}},
		}
	}

	unified := schema.Unify(inputValue)
	if unified.Err() != nil {
		errors := v.extractErrors(unified.Err())
		return &ValidationResult{
			Valid:  false,
			Errors: errors,
		}
	}

	if err := unified.Validate(cue.Concrete(true)); err != nil {
		errors := v.extractErrors(err)
		return &ValidationResult{
			Valid:  false,
			Errors: errors,
		}
	}

	return &ValidationResult{Valid: true}
}

func (v *Validator) extractErrors(err error) []*ValidationError {
	// Parse CUE error to extract field-level information
	errStr := err.Error()
	var errors []*ValidationError

	// Simple parsing - in production, use cue/errors package
	lines := strings.Split(errStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		ve := &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: line,
		}

		// Try to extract field path
		if idx := strings.Index(line, ":"); idx > 0 {
			field := strings.TrimSpace(line[:idx])
			if isFieldPath(field) {
				ve.Field = field
				ve.Message = strings.TrimSpace(line[idx+1:])
			}
		}

		errors = append(errors, ve)
	}

	if len(errors) == 0 {
		errors = append(errors, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: errStr,
		})
	}

	return errors
}

func isFieldPath(s string) bool {
	// Simple heuristic: field paths contain only alphanumeric, dots, and brackets
	matched, _ := regexp.MatchString(`^[a-zA-Z_][a-zA-Z0-9_.\[\]]*$`, s)
	return matched
}

// QuickValidator provides simple type-based validation without CUE.
type QuickValidator struct {
	rules map[string][]Rule
}

// Rule is a validation rule for a field.
type Rule struct {
	Field    string
	Required bool
	Type     string // string, number, bool, array, object
	Min      *float64
	Max      *float64
	MinLen   *int
	MaxLen   *int
	Pattern  string
	Enum     []interface{}
	Custom   func(value interface{}) error
}

// NewQuickValidator creates a quick validator.
func NewQuickValidator() *QuickValidator {
	return &QuickValidator{
		rules: make(map[string][]Rule),
	}
}

// AddRules adds validation rules for a policy.
func (qv *QuickValidator) AddRules(policyName string, rules []Rule) {
	qv.rules[policyName] = rules
}

// Validate validates input against rules.
func (qv *QuickValidator) Validate(policyName string, input map[string]interface{}) *ValidationResult {
	rules, exists := qv.rules[policyName]
	if !exists {
		return &ValidationResult{Valid: true}
	}

	var errors []*ValidationError

	for _, rule := range rules {
		value, exists := getNestedValue(input, rule.Field)

		// Check required
		if rule.Required && !exists {
			errors = append(errors, &ValidationError{
				Field:   rule.Field,
				Code:    "REQUIRED",
				Message: "field is required",
			})
			continue
		}

		if !exists {
			continue
		}

		// Check type
		if rule.Type != "" {
			if err := checkType(rule.Field, value, rule.Type); err != nil {
				errors = append(errors, err)
				continue
			}
		}

		// Check numeric constraints
		if rule.Min != nil || rule.Max != nil {
			if num, ok := toFloat64(value); ok {
				if rule.Min != nil && num < *rule.Min {
					errors = append(errors, &ValidationError{
						Field:    rule.Field,
						Code:     "MIN",
						Message:  fmt.Sprintf("value must be >= %v", *rule.Min),
						Expected: fmt.Sprintf(">= %v", *rule.Min),
						Actual:   fmt.Sprintf("%v", num),
					})
				}
				if rule.Max != nil && num > *rule.Max {
					errors = append(errors, &ValidationError{
						Field:    rule.Field,
						Code:     "MAX",
						Message:  fmt.Sprintf("value must be <= %v", *rule.Max),
						Expected: fmt.Sprintf("<= %v", *rule.Max),
						Actual:   fmt.Sprintf("%v", num),
					})
				}
			}
		}

		// Check string length
		if rule.MinLen != nil || rule.MaxLen != nil {
			if str, ok := value.(string); ok {
				if rule.MinLen != nil && len(str) < *rule.MinLen {
					errors = append(errors, &ValidationError{
						Field:    rule.Field,
						Code:     "MIN_LENGTH",
						Message:  fmt.Sprintf("length must be >= %d", *rule.MinLen),
						Expected: fmt.Sprintf(">= %d chars", *rule.MinLen),
						Actual:   fmt.Sprintf("%d chars", len(str)),
					})
				}
				if rule.MaxLen != nil && len(str) > *rule.MaxLen {
					errors = append(errors, &ValidationError{
						Field:    rule.Field,
						Code:     "MAX_LENGTH",
						Message:  fmt.Sprintf("length must be <= %d", *rule.MaxLen),
						Expected: fmt.Sprintf("<= %d chars", *rule.MaxLen),
						Actual:   fmt.Sprintf("%d chars", len(str)),
					})
				}
			}
		}

		// Check pattern
		if rule.Pattern != "" {
			if str, ok := value.(string); ok {
				matched, _ := regexp.MatchString(rule.Pattern, str)
				if !matched {
					errors = append(errors, &ValidationError{
						Field:    rule.Field,
						Code:     "PATTERN",
						Message:  fmt.Sprintf("value must match pattern: %s", rule.Pattern),
						Expected: rule.Pattern,
						Actual:   str,
					})
				}
			}
		}

		// Check enum
		if len(rule.Enum) > 0 {
			found := false
			for _, allowed := range rule.Enum {
				if reflect.DeepEqual(value, allowed) {
					found = true
					break
				}
			}
			if !found {
				errors = append(errors, &ValidationError{
					Field:    rule.Field,
					Code:     "ENUM",
					Message:  fmt.Sprintf("value must be one of: %v", rule.Enum),
					Expected: fmt.Sprintf("%v", rule.Enum),
					Actual:   fmt.Sprintf("%v", value),
				})
			}
		}

		// Custom validation
		if rule.Custom != nil {
			if err := rule.Custom(value); err != nil {
				errors = append(errors, &ValidationError{
					Field:   rule.Field,
					Code:    "CUSTOM",
					Message: err.Error(),
				})
			}
		}
	}

	return &ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

func checkType(field string, value interface{}, expectedType string) *ValidationError {
	var actualType string

	switch value.(type) {
	case string:
		actualType = "string"
	case float64, float32, int, int32, int64:
		actualType = "number"
	case bool:
		actualType = "bool"
	case []interface{}:
		actualType = "array"
	case map[string]interface{}:
		actualType = "object"
	default:
		actualType = reflect.TypeOf(value).String()
	}

	if actualType != expectedType {
		return &ValidationError{
			Field:    field,
			Code:     "TYPE",
			Message:  fmt.Sprintf("expected %s, got %s", expectedType, actualType),
			Expected: expectedType,
			Actual:   actualType,
		}
	}

	return nil
}

func getNestedValue(data map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			current, ok = m[part]
			if !ok {
				return nil, false
			}
		} else {
			return nil, false
		}
	}

	return current, true
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
