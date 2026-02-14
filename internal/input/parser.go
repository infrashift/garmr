// internal/input/parser.go
// Package input provides input parsing for JSON and YAML formats.
package input

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Format represents the input format.
type Format string

const (
	FormatJSON Format = "json"
	FormatYAML Format = "yaml"
	FormatAuto Format = "auto"
)

// Common errors.
var (
	ErrUnsupportedFormat = errors.New("unsupported input format")
	ErrParseFailure      = errors.New("failed to parse input")
)

// Parser handles input parsing for multiple formats.
type Parser struct {
	// DefaultFormat is used when format cannot be auto-detected.
	DefaultFormat Format
}

// NewParser creates a new input parser.
func NewParser() *Parser {
	return &Parser{
		DefaultFormat: FormatJSON,
	}
}

// ParseFile reads and parses a file, auto-detecting format from extension.
func (p *Parser) ParseFile(path string) (map[string]any, Format, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read file: %w", err)
	}

	format := p.DetectFormatFromPath(path)
	result, err := p.Parse(data, format)
	if err != nil {
		return nil, "", err
	}

	return result, format, nil
}

// Parse parses input data in the specified format.
// If format is FormatAuto, it attempts to detect the format.
func (p *Parser) Parse(data []byte, format Format) (map[string]any, error) {
	if format == FormatAuto || format == "" {
		format = p.DetectFormat(data)
	}

	switch format {
	case FormatJSON:
		return p.parseJSON(data)
	case FormatYAML:
		return p.parseYAML(data)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}
}

// ParseBytes is a convenience method that auto-detects format.
func (p *Parser) ParseBytes(data []byte) (map[string]any, error) {
	return p.Parse(data, FormatAuto)
}

// DetectFormat attempts to detect the format from content.
func (p *Parser) DetectFormat(data []byte) Format {
	// Trim whitespace
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return p.DefaultFormat
	}

	// JSON starts with { or [
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return FormatJSON
	}

	// Check for common YAML indicators
	if strings.HasPrefix(trimmed, "---") ||
		strings.Contains(trimmed, ":\n") ||
		strings.Contains(trimmed, ": ") {
		return FormatYAML
	}

	return p.DefaultFormat
}

// DetectFormatFromPath detects format from file extension.
func (p *Parser) DetectFormatFromPath(path string) Format {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return FormatJSON
	case ".yaml", ".yml":
		return FormatYAML
	default:
		return FormatAuto
	}
}

// DetectFormatFromContentType detects format from HTTP Content-Type header.
func (p *Parser) DetectFormatFromContentType(contentType string) Format {
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "application/json"):
		return FormatJSON
	case strings.Contains(ct, "application/x-yaml"),
		strings.Contains(ct, "application/yaml"),
		strings.Contains(ct, "text/yaml"),
		strings.Contains(ct, "text/x-yaml"):
		return FormatYAML
	default:
		return FormatAuto
	}
}

// parseJSON parses JSON input.
func (p *Parser) parseJSON(data []byte) (map[string]any, error) {
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrParseFailure, err)
	}
	return result, nil
}

// parseYAML parses YAML input.
func (p *Parser) parseYAML(data []byte) (map[string]any, error) {
	var result map[string]any
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("%w: invalid YAML: %v", ErrParseFailure, err)
	}
	return result, nil
}

// ToJSON converts a map to JSON bytes.
func ToJSON(data map[string]any) ([]byte, error) {
	return json.Marshal(data)
}

// ToJSONIndent converts a map to indented JSON bytes.
func ToJSONIndent(data map[string]any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(data, prefix, indent)
}

// ToYAML converts a map to YAML bytes.
func ToYAML(data map[string]any) ([]byte, error) {
	return yaml.Marshal(data)
}

// FormatString returns a string representation of the format.
func (f Format) String() string {
	return string(f)
}

// ParseFormat parses a format string.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "json":
		return FormatJSON, nil
	case "yaml", "yml":
		return FormatYAML, nil
	case "auto", "":
		return FormatAuto, nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, s)
	}
}

// SupportedFormats returns list of supported input formats.
func SupportedFormats() []Format {
	return []Format{FormatJSON, FormatYAML}
}

// SupportedExtensions returns list of supported file extensions.
func SupportedExtensions() []string {
	return []string{".json", ".yaml", ".yml"}
}
