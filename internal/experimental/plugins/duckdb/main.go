// plugins/duckdb/main.go
// Package main provides the DuckDB storage plugin for Q Policy Agent.
// DuckDB is useful for:
//   - Caching policies with SQL queryability
//   - Analytics on policy usage
//   - Embedded database (no external dependencies)
//
// Build with:
//   CGO_ENABLED=1 go build -buildmode=plugin -o duckdb.so ./plugins/duckdb
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	_ "github.com/marcboeker/go-duckdb"

	"github.com/infrashift/q-policy-agent/internal/plugin"
	"github.com/infrashift/q-policy-agent/internal/storage"
)

// DuckDBPlugin implements storage using embedded DuckDB.
type DuckDBPlugin struct {
	db      *sql.DB
	config  DuckDBConfig
	backend *DuckDBBackend
}

// DuckDBConfig configures the DuckDB plugin.
type DuckDBConfig struct {
	Database  string `json:"database"`  // Path or ":memory:"
	TableName string `json:"tableName"` // Table for policies
	ReadOnly  bool   `json:"readOnly"`
	PoolSize  int    `json:"poolSize"`
}

func (p *DuckDBPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "duckdb",
		Type:        plugin.TypeStorage,
		Version:     "1.0.0",
		Description: "Embedded DuckDB storage backend. Useful for caching, analytics, and SQL-queryable policy storage.",
		Author:      "Q Policy Agent",
		License:     "Apache-2.0",
		MinQVersion: "1.0.0",
		Capabilities: []string{
			"storage.read",
			"storage.checksum",
			"storage.sql", // Can query policies with SQL
		},
	}
}

func (p *DuckDBPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = DuckDBConfig{
		Database:  ":memory:",
		TableName: "policies",
		ReadOnly:  true,
		PoolSize:  4,
	}

	if v, ok := config["database"].(string); ok {
		p.config.Database = v
	}
	if v, ok := config["tableName"].(string); ok {
		p.config.TableName = v
	}
	if v, ok := config["readOnly"].(bool); ok {
		p.config.ReadOnly = v
	}
	if v, ok := config["poolSize"].(int); ok {
		p.config.PoolSize = v
	}

	// Build connection string
	connStr := p.config.Database
	if p.config.ReadOnly && p.config.Database != ":memory:" {
		connStr += "?access_mode=read_only"
	}

	// Open database
	db, err := sql.Open("duckdb", connStr)
	if err != nil {
		return fmt.Errorf("duckdb: opening database: %w", err)
	}

	db.SetMaxOpenConns(p.config.PoolSize)
	db.SetMaxIdleConns(p.config.PoolSize)

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("duckdb: ping failed: %w", err)
	}

	// Create table if not exists (for non-read-only mode)
	if !p.config.ReadOnly {
		_, err = db.ExecContext(ctx, fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				path VARCHAR PRIMARY KEY,
				namespace VARCHAR,
				name VARCHAR,
				content BLOB,
				checksum VARCHAR,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
		`, p.config.TableName))
		if err != nil {
			db.Close()
			return fmt.Errorf("duckdb: creating table: %w", err)
		}
	}

	p.db = db
	p.backend = &DuckDBBackend{
		db:        db,
		tableName: p.config.TableName,
	}

	return nil
}

func (p *DuckDBPlugin) Health(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *DuckDBPlugin) Close() error {
	if p.db != nil {
		return p.db.Close()
	}
	return nil
}

func (p *DuckDBPlugin) Backend() storage.Backend {
	return p.backend
}

// Query executes a SQL query against the policy database.
// This is a DuckDB-specific extension for analytics.
func (p *DuckDBPlugin) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return p.db.QueryContext(ctx, query, args...)
}

// DuckDBBackend implements storage.Backend for DuckDB.
type DuckDBBackend struct {
	db        *sql.DB
	tableName string
	mu        sync.RWMutex
}

func (b *DuckDBBackend) Type() string {
	return "duckdb"
}

func (b *DuckDBBackend) List(ctx context.Context, pattern string) ([]storage.FileInfo, error) {
	query := fmt.Sprintf(`
		SELECT path, length(content) as size, checksum, updated_at
		FROM %s
		WHERE path LIKE '%%' || $1 || '%%'
		ORDER BY path
	`, b.tableName)

	// Convert glob to SQL LIKE pattern
	sqlPattern := strings.ReplaceAll(pattern, "**", "%")
	sqlPattern = strings.ReplaceAll(sqlPattern, "*", "%")
	if sqlPattern == "" {
		sqlPattern = "%"
	}

	rows, err := b.db.QueryContext(ctx, query, sqlPattern)
	if err != nil {
		return nil, fmt.Errorf("duckdb: listing: %w", err)
	}
	defer rows.Close()

	var files []storage.FileInfo
	for rows.Next() {
		var path, checksum string
		var size int64
		var updatedAt time.Time

		if err := rows.Scan(&path, &size, &checksum, &updatedAt); err != nil {
			return nil, err
		}

		files = append(files, storage.FileInfo{
			Path:     path,
			Size:     size,
			ModTime:  updatedAt,
			Checksum: checksum,
		})
	}

	return files, rows.Err()
}

func (b *DuckDBBackend) Get(ctx context.Context, filePath string) ([]byte, error) {
	query := fmt.Sprintf(`SELECT content FROM %s WHERE path = $1`, b.tableName)

	var content []byte
	err := b.db.QueryRowContext(ctx, query, filePath).Scan(&content)
	if err == sql.ErrNoRows {
		return nil, &storage.ErrNotFound{Path: filePath}
	}
	if err != nil {
		return nil, fmt.Errorf("duckdb: getting %s: %w", filePath, err)
	}

	return content, nil
}

func (b *DuckDBBackend) GetReader(ctx context.Context, filePath string) (io.ReadCloser, error) {
	content, err := b.Get(ctx, filePath)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(strings.NewReader(string(content))), nil
}

func (b *DuckDBBackend) Stat(ctx context.Context, filePath string) (*storage.FileInfo, error) {
	query := fmt.Sprintf(`
		SELECT path, length(content), checksum, updated_at
		FROM %s
		WHERE path = $1
	`, b.tableName)

	var path, checksum string
	var size int64
	var updatedAt time.Time

	err := b.db.QueryRowContext(ctx, query, filePath).Scan(&path, &size, &checksum, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, &storage.ErrNotFound{Path: filePath}
	}
	if err != nil {
		return nil, fmt.Errorf("duckdb: stat %s: %w", filePath, err)
	}

	return &storage.FileInfo{
		Path:     path,
		Size:     size,
		ModTime:  updatedAt,
		Checksum: checksum,
	}, nil
}

func (b *DuckDBBackend) Checksum(ctx context.Context, filePath string) (string, error) {
	query := fmt.Sprintf(`SELECT checksum FROM %s WHERE path = $1`, b.tableName)

	var checksum string
	err := b.db.QueryRowContext(ctx, query, filePath).Scan(&checksum)
	if err == sql.ErrNoRows {
		return "", &storage.ErrNotFound{Path: filePath}
	}
	if err != nil {
		return "", err
	}

	return checksum, nil
}

// Watch is not supported for DuckDB (no change notification mechanism).
func (b *DuckDBBackend) Watch(ctx context.Context, pattern string) (<-chan storage.Event, error) {
	return nil, nil
}

func (b *DuckDBBackend) Close() error {
	return nil // DB is closed by plugin
}

// Put stores a policy in DuckDB (for write mode).
func (b *DuckDBBackend) Put(ctx context.Context, filePath, namespace, name string, content []byte) error {
	hash := sha256.Sum256(content)
	checksum := "sha256:" + hex.EncodeToString(hash[:])

	query := fmt.Sprintf(`
		INSERT INTO %s (path, namespace, name, content, checksum, updated_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
		ON CONFLICT (path) DO UPDATE SET
			namespace = EXCLUDED.namespace,
			name = EXCLUDED.name,
			content = EXCLUDED.content,
			checksum = EXCLUDED.checksum,
			updated_at = CURRENT_TIMESTAMP
	`, b.tableName)

	_, err := b.db.ExecContext(ctx, query, filePath, namespace, name, content, checksum)
	return err
}

// Delete removes a policy from DuckDB.
func (b *DuckDBBackend) Delete(ctx context.Context, filePath string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE path = $1`, b.tableName)
	_, err := b.db.ExecContext(ctx, query, filePath)
	return err
}

// Compile-time checks
var _ plugin.StoragePlugin = (*DuckDBPlugin)(nil)
var _ storage.Backend = (*DuckDBBackend)(nil)

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &DuckDBPlugin{}
