package input

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Fatal("NewParser returned nil")
		return
	}
	if p.DefaultFormat != FormatJSON {
		t.Errorf("expected default format JSON, got %s", p.DefaultFormat)
	}
}

// --- JSON Parsing ---

func TestParseJSON(t *testing.T) {
	p := NewParser()
	data := []byte(`{"name": "test", "count": 42, "nested": {"key": "value"}}`)
	result, err := p.Parse(data, FormatJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
	nested, ok := result["nested"].(map[string]any)
	if !ok {
		t.Fatal("nested is not a map")
	}
	if nested["key"] != "value" {
		t.Errorf("expected nested.key=value, got %v", nested["key"])
	}
}

func TestParseJSON_Array(t *testing.T) {
	p := NewParser()
	data := []byte(`{"items": [1, 2, 3]}`)
	result, err := p.Parse(data, FormatJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	items, ok := result["items"].([]any)
	if !ok {
		t.Fatal("items is not an array")
	}
	if len(items) != 3 {
		t.Errorf("expected 3 items, got %d", len(items))
	}
}

func TestParseJSON_Invalid(t *testing.T) {
	p := NewParser()
	data := []byte(`{invalid json}`)
	_, err := p.Parse(data, FormatJSON)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- YAML Parsing ---

func TestParseYAML(t *testing.T) {
	p := NewParser()
	data := []byte("name: test\ncount: 42\nnested:\n  key: value\n")
	result, err := p.Parse(data, FormatYAML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("expected name=test, got %v", result["name"])
	}
	nested, ok := result["nested"].(map[string]any)
	if !ok {
		t.Fatal("nested is not a map")
	}
	if nested["key"] != "value" {
		t.Errorf("expected nested.key=value, got %v", nested["key"])
	}
}

func TestParseYAML_Invalid(t *testing.T) {
	p := NewParser()
	data := []byte(":\n  - :\n  invalid: [")
	_, err := p.Parse(data, FormatYAML)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// --- Auto-detection from Content ---

func TestDetectFormat_JSON(t *testing.T) {
	p := NewParser()
	data := []byte(`{"key": "value"}`)
	if f := p.DetectFormat(data); f != FormatJSON {
		t.Errorf("expected JSON, got %s", f)
	}
}

func TestDetectFormat_JSONArray(t *testing.T) {
	p := NewParser()
	data := []byte(`[1, 2, 3]`)
	if f := p.DetectFormat(data); f != FormatJSON {
		t.Errorf("expected JSON, got %s", f)
	}
}

func TestDetectFormat_YAML_Dashes(t *testing.T) {
	p := NewParser()
	data := []byte("---\nname: test\n")
	if f := p.DetectFormat(data); f != FormatYAML {
		t.Errorf("expected YAML, got %s", f)
	}
}

func TestDetectFormat_YAML_Colon(t *testing.T) {
	p := NewParser()
	data := []byte("name: test\n")
	if f := p.DetectFormat(data); f != FormatYAML {
		t.Errorf("expected YAML, got %s", f)
	}
}

func TestDetectFormat_Empty(t *testing.T) {
	p := NewParser()
	if f := p.DetectFormat([]byte("")); f != FormatJSON {
		t.Errorf("expected default JSON for empty input, got %s", f)
	}
}

// --- Format from Path ---

func TestDetectFormatFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected Format
	}{
		{"policy.json", FormatJSON},
		{"policy.yaml", FormatYAML},
		{"policy.yml", FormatYAML},
		{"policy.cue", FormatAuto},
		{"policy.JSON", FormatJSON},
		{"policy", FormatAuto},
	}
	p := NewParser()
	for _, tt := range tests {
		if f := p.DetectFormatFromPath(tt.path); f != tt.expected {
			t.Errorf("DetectFormatFromPath(%q) = %s, want %s", tt.path, f, tt.expected)
		}
	}
}

// --- Format from Content-Type ---

func TestDetectFormatFromContentType(t *testing.T) {
	tests := []struct {
		ct       string
		expected Format
	}{
		{"application/json", FormatJSON},
		{"application/json; charset=utf-8", FormatJSON},
		{"application/yaml", FormatYAML},
		{"application/x-yaml", FormatYAML},
		{"text/yaml", FormatYAML},
		{"text/x-yaml", FormatYAML},
		{"text/plain", FormatAuto},
		{"", FormatAuto},
	}
	p := NewParser()
	for _, tt := range tests {
		if f := p.DetectFormatFromContentType(tt.ct); f != tt.expected {
			t.Errorf("DetectFormatFromContentType(%q) = %s, want %s", tt.ct, f, tt.expected)
		}
	}
}

// --- ParseFile ---

func TestParseFile_JSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	if err := os.WriteFile(path, []byte(`{"kind": "Pod"}`), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewParser()
	result, format, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if format != FormatJSON {
		t.Errorf("expected JSON format, got %s", format)
	}
	if result["kind"] != "Pod" {
		t.Errorf("expected kind=Pod, got %v", result["kind"])
	}
}

func TestParseFile_YAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.yaml")
	if err := os.WriteFile(path, []byte("kind: Deployment\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p := NewParser()
	result, format, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if format != FormatYAML {
		t.Errorf("expected YAML format, got %s", format)
	}
	if result["kind"] != "Deployment" {
		t.Errorf("expected kind=Deployment, got %v", result["kind"])
	}
}

func TestParseFile_NotFound(t *testing.T) {
	p := NewParser()
	_, _, err := p.ParseFile("/nonexistent/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// --- ParseFormat ---

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
		wantErr  bool
	}{
		{"json", FormatJSON, false},
		{"yaml", FormatYAML, false},
		{"yml", FormatYAML, false},
		{"auto", FormatAuto, false},
		{"", FormatAuto, false},
		{"xml", "", true},
		{"toml", "", true},
	}
	for _, tt := range tests {
		f, err := ParseFormat(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if f != tt.expected {
			t.Errorf("ParseFormat(%q) = %s, want %s", tt.input, f, tt.expected)
		}
	}
}

func TestParse_UnsupportedFormat(t *testing.T) {
	p := NewParser()
	_, err := p.Parse([]byte("data"), Format("xml"))
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

// --- Format.String ---

func TestFormat_String(t *testing.T) {
	if FormatJSON.String() != "json" {
		t.Errorf("expected 'json', got %s", FormatJSON.String())
	}
	if FormatYAML.String() != "yaml" {
		t.Errorf("expected 'yaml', got %s", FormatYAML.String())
	}
}
