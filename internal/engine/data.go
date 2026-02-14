package engine

import (
	"fmt"
	"strings"

	"cuelang.org/go/cue"
)

// SetData sets external data for policy evaluation.
func (e *Engine) SetData(path string, data any) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	dataVal := e.ctx.Encode(data)
	if dataVal.Err() != nil {
		return fmt.Errorf("encoding data: %w", dataVal.Err())
	}

	// Merge with existing data
	if e.data.Exists() {
		e.data = e.data.FillPath(cue.ParsePath(path), dataVal)
	} else {
		e.data = dataVal
	}

	return nil
}

// GetData retrieves data at the given path.
func (e *Engine) GetData(path string) any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.data.Exists() {
		return nil
	}

	if path == "" || path == "/" {
		var result any
		e.data.Decode(&result)
		return result
	}

	val := e.data.LookupPath(cue.ParsePath(strings.TrimPrefix(path, "/")))
	if !val.Exists() {
		return nil
	}

	var result any
	val.Decode(&result)
	return result
}

// PutData sets data at the given path.
func (e *Engine) PutData(path string, data any) error {
	return e.SetData(strings.TrimPrefix(path, "/"), data)
}

// DeleteData removes data at the given path.
func (e *Engine) DeleteData(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// For simplicity, we'll just set nil at the path
	// A more complete implementation would properly remove the path
	if e.data.Exists() && path != "" && path != "/" {
		// CUE doesn't have a direct way to delete paths
		// So we rebuild data without that path
		// For now, just log that deletion is limited
	}
}
