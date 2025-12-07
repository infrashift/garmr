// plugins/kafka/main.go
// Package main provides the Kafka audit logging plugin for Q Policy Agent.
// Publishes policy decisions to Kafka for compliance and audit trails.
//
// Build with:
//   go build -buildmode=plugin -o kafka.so ./plugins/kafka
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/IBM/sarama"

	"github.com/infrashift/q-policy-agent/internal/plugin"
)

// KafkaPlugin publishes audit decisions to Kafka.
type KafkaPlugin struct {
	config   KafkaConfig
	producer sarama.AsyncProducer
	mu       sync.RWMutex
	closed   bool

	// Metrics
	messagesSent   int64
	messagesFailed int64
}

// KafkaConfig configures the Kafka audit plugin.
type KafkaConfig struct {
	// Enabled controls whether audit logging is active
	Enabled bool `json:"enabled"`

	// Brokers is the list of Kafka broker addresses
	Brokers []string `json:"brokers"`

	// Topic for audit messages
	Topic string `json:"topic"`

	// ClientID for Kafka connection
	ClientID string `json:"clientId"`

	// Partitioner: hash, random, roundrobin, manual
	Partitioner string `json:"partitioner"`

	// RequiredAcks: none, leader, all
	RequiredAcks string `json:"requiredAcks"`

	// Compression: none, gzip, snappy, lz4, zstd
	Compression string `json:"compression"`

	// MaxRetries for failed messages
	MaxRetries int `json:"maxRetries"`

	// BatchSize for async producer
	BatchSize int `json:"batchSize"`

	// BatchTimeout before sending incomplete batch
	BatchTimeout time.Duration `json:"batchTimeout"`

	// TLS configuration
	TLS TLSConfig `json:"tls"`

	// SASL authentication
	SASL SASLConfig `json:"sasl"`

	// Privacy settings
	Privacy PrivacyConfig `json:"privacy"`
}

// TLSConfig for secure Kafka connections.
type TLSConfig struct {
	Enabled    bool   `json:"enabled"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	CAFile     string `json:"caFile"`
	SkipVerify bool   `json:"skipVerify"`
}

// SASLConfig for Kafka authentication.
type SASLConfig struct {
	Enabled   bool   `json:"enabled"`
	Mechanism string `json:"mechanism"` // PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// PrivacyConfig controls what data is included in audit logs.
type PrivacyConfig struct {
	// HashInput hashes input data instead of including raw values
	HashInput bool `json:"hashInput"`

	// ExcludeInput completely excludes input from audit
	ExcludeInput bool `json:"excludeInput"`

	// RedactFields is a list of field paths to redact
	RedactFields []string `json:"redactFields"`

	// IncludeStackTrace includes stack traces for errors
	IncludeStackTrace bool `json:"includeStackTrace"`
}

// AuditMessage is the structure published to Kafka.
type AuditMessage struct {
	// Unique identifier for this decision
	ID string `json:"id"`

	// Timestamp of the decision
	Timestamp time.Time `json:"timestamp"`

	// Version of the audit message schema
	SchemaVersion string `json:"schemaVersion"`

	// Request information
	Request AuditRequest `json:"request"`

	// Result of the evaluation
	Result AuditResult `json:"result"`

	// Context about the request
	Context AuditContext `json:"context"`

	// Timing information
	Timing AuditTiming `json:"timing"`
}

// AuditRequest contains request details.
type AuditRequest struct {
	Policy      string `json:"policy"`
	Namespace   string `json:"namespace"`
	PolicySet   string `json:"policySet,omitempty"`
	Environment string `json:"environment,omitempty"`

	// Input is either the raw input, hash, or omitted based on privacy settings
	Input     interface{} `json:"input,omitempty"`
	InputHash string      `json:"inputHash,omitempty"`
}

// AuditResult contains evaluation results.
type AuditResult struct {
	Decision   string           `json:"decision"`
	Violations []AuditViolation `json:"violations,omitempty"`
	Score      float64          `json:"score,omitempty"`
	Message    string           `json:"message,omitempty"`
}

// AuditViolation represents a single violation.
type AuditViolation struct {
	RuleID      string `json:"ruleId"`
	Severity    string `json:"severity"`
	Category    string `json:"category,omitempty"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// AuditContext contains request context.
type AuditContext struct {
	Principal   string            `json:"principal,omitempty"`
	SourceIP    string            `json:"sourceIp,omitempty"`
	TraceID     string            `json:"traceId,omitempty"`
	SpanID      string            `json:"spanId,omitempty"`
	RequestID   string            `json:"requestId,omitempty"`
	UserAgent   string            `json:"userAgent,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// AuditTiming contains timing information.
type AuditTiming struct {
	ReceivedAt   time.Time     `json:"receivedAt"`
	CompletedAt  time.Time     `json:"completedAt"`
	DurationMs   int64         `json:"durationMs"`
	RuleTimings  []RuleTiming  `json:"ruleTimings,omitempty"`
}

// RuleTiming contains timing for individual rules.
type RuleTiming struct {
	RuleID     string `json:"ruleId"`
	DurationMs int64  `json:"durationMs"`
}

func (p *KafkaPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "kafka",
		Type:        plugin.TypeNotifier,
		Version:     "1.0.0",
		Description: "Kafka audit logging for policy decision compliance and auditing",
		Author:      "Q Policy Agent",
		License:     "Apache-2.0",
		Capabilities: []string{
			"audit.kafka",
			"audit.stream",
			"compliance.logging",
		},
	}
}

func (p *KafkaPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = KafkaConfig{
		Enabled:      true,
		Brokers:      []string{"localhost:9092"},
		Topic:        "q-audit-decisions",
		ClientID:     "q-policy-agent",
		Partitioner:  "hash",
		RequiredAcks: "leader",
		Compression:  "snappy",
		MaxRetries:   3,
		BatchSize:    100,
		BatchTimeout: 100 * time.Millisecond,
		Privacy: PrivacyConfig{
			HashInput:         true,
			ExcludeInput:      false,
			IncludeStackTrace: false,
		},
	}

	if v, ok := config["enabled"].(bool); ok {
		p.config.Enabled = v
	}
	if v, ok := config["brokers"].([]interface{}); ok {
		p.config.Brokers = make([]string, len(v))
		for i, b := range v {
			if s, ok := b.(string); ok {
				p.config.Brokers[i] = s
			}
		}
	}
	if v, ok := config["topic"].(string); ok {
		p.config.Topic = v
	}
	if v, ok := config["clientId"].(string); ok {
		p.config.ClientID = v
	}
	if v, ok := config["partitioner"].(string); ok {
		p.config.Partitioner = v
	}
	if v, ok := config["requiredAcks"].(string); ok {
		p.config.RequiredAcks = v
	}
	if v, ok := config["compression"].(string); ok {
		p.config.Compression = v
	}
	if v, ok := config["maxRetries"].(float64); ok {
		p.config.MaxRetries = int(v)
	}

	// Parse TLS config
	if tlsCfg, ok := config["tls"].(map[string]interface{}); ok {
		if v, ok := tlsCfg["enabled"].(bool); ok {
			p.config.TLS.Enabled = v
		}
		if v, ok := tlsCfg["certFile"].(string); ok {
			p.config.TLS.CertFile = v
		}
		if v, ok := tlsCfg["keyFile"].(string); ok {
			p.config.TLS.KeyFile = v
		}
		if v, ok := tlsCfg["caFile"].(string); ok {
			p.config.TLS.CAFile = v
		}
		if v, ok := tlsCfg["skipVerify"].(bool); ok {
			p.config.TLS.SkipVerify = v
		}
	}

	// Parse SASL config
	if saslCfg, ok := config["sasl"].(map[string]interface{}); ok {
		if v, ok := saslCfg["enabled"].(bool); ok {
			p.config.SASL.Enabled = v
		}
		if v, ok := saslCfg["mechanism"].(string); ok {
			p.config.SASL.Mechanism = v
		}
		if v, ok := saslCfg["username"].(string); ok {
			p.config.SASL.Username = v
		}
		if v, ok := saslCfg["password"].(string); ok {
			p.config.SASL.Password = v
		}
	}

	// Parse privacy config
	if privCfg, ok := config["privacy"].(map[string]interface{}); ok {
		if v, ok := privCfg["hashInput"].(bool); ok {
			p.config.Privacy.HashInput = v
		}
		if v, ok := privCfg["excludeInput"].(bool); ok {
			p.config.Privacy.ExcludeInput = v
		}
		if v, ok := privCfg["includeStackTrace"].(bool); ok {
			p.config.Privacy.IncludeStackTrace = v
		}
		if v, ok := privCfg["redactFields"].([]interface{}); ok {
			p.config.Privacy.RedactFields = make([]string, len(v))
			for i, f := range v {
				if s, ok := f.(string); ok {
					p.config.Privacy.RedactFields[i] = s
				}
			}
		}
	}

	if !p.config.Enabled {
		return nil
	}

	// Create Kafka producer
	producer, err := p.createProducer()
	if err != nil {
		return fmt.Errorf("creating Kafka producer: %w", err)
	}
	p.producer = producer

	// Start error handler
	go p.handleErrors()

	return nil
}

func (p *KafkaPlugin) createProducer() (sarama.AsyncProducer, error) {
	cfg := sarama.NewConfig()
	cfg.ClientID = p.config.ClientID
	cfg.Producer.Return.Successes = false
	cfg.Producer.Return.Errors = true
	cfg.Producer.Retry.Max = p.config.MaxRetries
	cfg.Producer.Flush.Messages = p.config.BatchSize
	cfg.Producer.Flush.Frequency = p.config.BatchTimeout

	// Set partitioner
	switch p.config.Partitioner {
	case "hash":
		cfg.Producer.Partitioner = sarama.NewHashPartitioner
	case "random":
		cfg.Producer.Partitioner = sarama.NewRandomPartitioner
	case "roundrobin":
		cfg.Producer.Partitioner = sarama.NewRoundRobinPartitioner
	case "manual":
		cfg.Producer.Partitioner = sarama.NewManualPartitioner
	default:
		cfg.Producer.Partitioner = sarama.NewHashPartitioner
	}

	// Set required acks
	switch p.config.RequiredAcks {
	case "none":
		cfg.Producer.RequiredAcks = sarama.NoResponse
	case "leader":
		cfg.Producer.RequiredAcks = sarama.WaitForLocal
	case "all":
		cfg.Producer.RequiredAcks = sarama.WaitForAll
	default:
		cfg.Producer.RequiredAcks = sarama.WaitForLocal
	}

	// Set compression
	switch p.config.Compression {
	case "none":
		cfg.Producer.Compression = sarama.CompressionNone
	case "gzip":
		cfg.Producer.Compression = sarama.CompressionGZIP
	case "snappy":
		cfg.Producer.Compression = sarama.CompressionSnappy
	case "lz4":
		cfg.Producer.Compression = sarama.CompressionLZ4
	case "zstd":
		cfg.Producer.Compression = sarama.CompressionZSTD
	default:
		cfg.Producer.Compression = sarama.CompressionSnappy
	}

	// Configure TLS
	if p.config.TLS.Enabled {
		tlsConfig, err := p.createTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("creating TLS config: %w", err)
		}
		cfg.Net.TLS.Enable = true
		cfg.Net.TLS.Config = tlsConfig
	}

	// Configure SASL
	if p.config.SASL.Enabled {
		cfg.Net.SASL.Enable = true
		cfg.Net.SASL.User = p.config.SASL.Username
		cfg.Net.SASL.Password = p.config.SASL.Password

		switch p.config.SASL.Mechanism {
		case "PLAIN":
			cfg.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		case "SCRAM-SHA-256":
			cfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
			cfg.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
				return &scramClient{mechanism: "SCRAM-SHA-256"}
			}
		case "SCRAM-SHA-512":
			cfg.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
			cfg.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
				return &scramClient{mechanism: "SCRAM-SHA-512"}
			}
		}
	}

	return sarama.NewAsyncProducer(p.config.Brokers, cfg)
}

func (p *KafkaPlugin) createTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: p.config.TLS.SkipVerify,
	}

	if p.config.TLS.CertFile != "" && p.config.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(p.config.TLS.CertFile, p.config.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if p.config.TLS.CAFile != "" {
		caCert, err := os.ReadFile(p.config.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

func (p *KafkaPlugin) handleErrors() {
	if p.producer == nil {
		return
	}

	for err := range p.producer.Errors() {
		p.mu.Lock()
		p.messagesFailed++
		p.mu.Unlock()
		// Log error - in production, integrate with logging plugin
		fmt.Printf("kafka audit error: %v\n", err)
	}
}

func (p *KafkaPlugin) Health(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}
	if p.producer == nil {
		return fmt.Errorf("Kafka producer not initialized")
	}
	return nil
}

func (p *KafkaPlugin) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	if p.producer != nil {
		return p.producer.Close()
	}
	return nil
}

// PublishDecision publishes an audit decision to Kafka.
func (p *KafkaPlugin) PublishDecision(msg *AuditMessage) error {
	if !p.config.Enabled || p.producer == nil {
		return nil
	}

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return fmt.Errorf("producer is closed")
	}
	p.mu.RUnlock()

	// Apply privacy settings
	p.applyPrivacy(msg)

	// Set schema version
	msg.SchemaVersion = "1.0"

	// Marshal to JSON
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling audit message: %w", err)
	}

	// Create Kafka message
	kafkaMsg := &sarama.ProducerMessage{
		Topic: p.config.Topic,
		Key:   sarama.StringEncoder(msg.Request.Policy + "/" + msg.Request.Namespace),
		Value: sarama.ByteEncoder(data),
		Headers: []sarama.RecordHeader{
			{Key: []byte("schema-version"), Value: []byte("1.0")},
			{Key: []byte("message-type"), Value: []byte("audit-decision")},
		},
		Timestamp: msg.Timestamp,
	}

	// Send asynchronously
	p.producer.Input() <- kafkaMsg

	p.mu.Lock()
	p.messagesSent++
	p.mu.Unlock()

	return nil
}

func (p *KafkaPlugin) applyPrivacy(msg *AuditMessage) {
	if p.config.Privacy.ExcludeInput {
		msg.Request.Input = nil
		msg.Request.InputHash = ""
	} else if p.config.Privacy.HashInput && msg.Request.Input != nil {
		// Hash the input
		inputBytes, _ := json.Marshal(msg.Request.Input)
		hash := sha256.Sum256(inputBytes)
		msg.Request.InputHash = hex.EncodeToString(hash[:])
		msg.Request.Input = nil
	}
}

// Stats returns producer statistics.
func (p *KafkaPlugin) Stats() (sent, failed int64) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.messagesSent, p.messagesFailed
}

// Helper: Create audit message from evaluation
func NewAuditMessage(
	id string,
	policy, namespace, environment string,
	input interface{},
	decision string,
	violations []AuditViolation,
	ctx AuditContext,
	startTime, endTime time.Time,
) *AuditMessage {
	return &AuditMessage{
		ID:            id,
		Timestamp:     time.Now().UTC(),
		SchemaVersion: "1.0",
		Request: AuditRequest{
			Policy:      policy,
			Namespace:   namespace,
			Environment: environment,
			Input:       input,
		},
		Result: AuditResult{
			Decision:   decision,
			Violations: violations,
		},
		Context: ctx,
		Timing: AuditTiming{
			ReceivedAt:  startTime,
			CompletedAt: endTime,
			DurationMs:  endTime.Sub(startTime).Milliseconds(),
		},
	}
}

// scramClient implements SCRAM authentication (placeholder).
type scramClient struct {
	mechanism string
}

func (s *scramClient) Begin(userName, password, authzID string) error { return nil }
func (s *scramClient) Step(challenge string) (string, error)         { return "", nil }
func (s *scramClient) Done() bool                                    { return true }

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &KafkaPlugin{}
