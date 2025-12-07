// internal/plugin/signing.go
// Package plugin provides cryptographic signing and verification for Q plugins.
// Uses Ed25519 for signatures - simple, fast, and secure.
//
// Security Model:
//   1. Plugin author signs plugin with their private key
//   2. Q administrator adds author's public key to trusted keys
//   3. At load time, Q verifies both checksum and signature
//   4. Plugin only loads if signature is valid AND key is trusted
//
// File Format:
//   plugin.so        - The plugin binary
//   plugin.so.sig    - Ed25519 signature of SHA256(plugin.so)
//   plugin.so.sum    - SHA256 checksum (human-readable)
package plugin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Signature-related errors
var (
	ErrSignatureInvalid    = errors.New("signature verification failed")
	ErrSignatureMissing    = errors.New("signature file not found")
	ErrKeyNotTrusted       = errors.New("signing key not in trusted keys")
	ErrChecksumMismatch    = errors.New("checksum verification failed")
	ErrInvalidKeyFormat    = errors.New("invalid key format")
	ErrInvalidSignature    = errors.New("invalid signature format")
)

const (
	// SignatureExtension is appended to plugin filename for signature
	SignatureExtension = ".sig"
	
	// ChecksumExtension is appended to plugin filename for checksum
	ChecksumExtension = ".sum"
	
	// KeyIDLength is the length of key identifier (first 8 bytes of public key hash)
	KeyIDLength = 8
	
	// SignatureVersion for format evolution
	SignatureVersion = 1
)

// Signature contains a plugin signature and metadata.
type Signature struct {
	// Version of signature format
	Version int `json:"version"`
	
	// KeyID identifies the signing key (first 8 bytes of SHA256(pubkey))
	KeyID string `json:"keyId"`
	
	// Algorithm used (always "ed25519" for now)
	Algorithm string `json:"algorithm"`
	
	// Checksum of the signed content (SHA256)
	Checksum string `json:"checksum"`
	
	// Signature bytes (base64-encoded Ed25519 signature)
	Signature string `json:"signature"`
	
	// Timestamp when signature was created
	Timestamp time.Time `json:"timestamp"`
	
	// Comment (optional, e.g., plugin name and version)
	Comment string `json:"comment,omitempty"`
}

// SigningKey represents an Ed25519 key pair for signing.
type SigningKey struct {
	// ID is the key identifier (first 8 bytes of SHA256(public key))
	ID string
	
	// Public key bytes
	Public ed25519.PublicKey
	
	// Private key bytes (nil for verification-only keys)
	Private ed25519.PrivateKey
	
	// Comment describing the key (e.g., "Q Plugin Signing Key - Production")
	Comment string
	
	// Created timestamp
	Created time.Time
}

// TrustedKeys manages the set of keys trusted for plugin verification.
type TrustedKeys struct {
	keys map[string]*SigningKey // keyID -> key
}

// NewTrustedKeys creates an empty trusted key set.
func NewTrustedKeys() *TrustedKeys {
	return &TrustedKeys{
		keys: make(map[string]*SigningKey),
	}
}

// Add adds a public key to the trusted set.
func (tk *TrustedKeys) Add(key *SigningKey) error {
	if key.Public == nil {
		return ErrInvalidKeyFormat
	}
	tk.keys[key.ID] = key
	return nil
}

// AddFromBase64 adds a public key from base64 encoding.
func (tk *TrustedKeys) AddFromBase64(encoded, comment string) error {
	key, err := ParsePublicKey(encoded)
	if err != nil {
		return err
	}
	key.Comment = comment
	return tk.Add(key)
}

// Get retrieves a key by ID.
func (tk *TrustedKeys) Get(keyID string) (*SigningKey, bool) {
	key, ok := tk.keys[keyID]
	return key, ok
}

// IsTrusted checks if a key ID is in the trusted set.
func (tk *TrustedKeys) IsTrusted(keyID string) bool {
	_, ok := tk.keys[keyID]
	return ok
}

// List returns all trusted keys.
func (tk *TrustedKeys) List() []*SigningKey {
	result := make([]*SigningKey, 0, len(tk.keys))
	for _, key := range tk.keys {
		result = append(result, key)
	}
	return result
}

// GenerateKey creates a new Ed25519 signing key pair.
func GenerateKey(comment string) (*SigningKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	
	return &SigningKey{
		ID:      computeKeyID(public),
		Public:  public,
		Private: private,
		Comment: comment,
		Created: time.Now().UTC(),
	}, nil
}

// ParsePublicKey parses a base64-encoded public key.
func ParsePublicKey(encoded string) (*SigningKey, error) {
	// Remove any whitespace
	encoded = strings.TrimSpace(encoded)
	
	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidKeyFormat, err)
	}
	
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", 
			ErrInvalidKeyFormat, ed25519.PublicKeySize, len(decoded))
	}
	
	public := ed25519.PublicKey(decoded)
	
	return &SigningKey{
		ID:     computeKeyID(public),
		Public: public,
	}, nil
}

// ParsePrivateKey parses a base64-encoded private key.
func ParsePrivateKey(encoded string) (*SigningKey, error) {
	encoded = strings.TrimSpace(encoded)
	
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidKeyFormat, err)
	}
	
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d",
			ErrInvalidKeyFormat, ed25519.PrivateKeySize, len(decoded))
	}
	
	private := ed25519.PrivateKey(decoded)
	public := private.Public().(ed25519.PublicKey)
	
	return &SigningKey{
		ID:      computeKeyID(public),
		Public:  public,
		Private: private,
	}, nil
}

// EncodePublic returns the base64-encoded public key.
func (k *SigningKey) EncodePublic() string {
	return base64.StdEncoding.EncodeToString(k.Public)
}

// EncodePrivate returns the base64-encoded private key.
func (k *SigningKey) EncodePrivate() string {
	if k.Private == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(k.Private)
}

// Sign signs data with the private key.
func (k *SigningKey) Sign(data []byte) ([]byte, error) {
	if k.Private == nil {
		return nil, errors.New("no private key available")
	}
	
	signature := ed25519.Sign(k.Private, data)
	return signature, nil
}

// Verify verifies a signature against data.
func (k *SigningKey) Verify(data, signature []byte) bool {
	return ed25519.Verify(k.Public, data, signature)
}

// computeKeyID computes the key identifier from a public key.
func computeKeyID(public ed25519.PublicKey) string {
	hash := sha256.Sum256(public)
	return hex.EncodeToString(hash[:KeyIDLength])
}

// Signer handles plugin signing operations.
type Signer struct {
	key *SigningKey
}

// NewSigner creates a new signer with the given private key.
func NewSigner(key *SigningKey) (*Signer, error) {
	if key.Private == nil {
		return nil, errors.New("private key required for signing")
	}
	return &Signer{key: key}, nil
}

// SignFile signs a plugin file and writes signature files.
func (s *Signer) SignFile(pluginPath string, comment string) error {
	// Read plugin content
	content, err := os.ReadFile(pluginPath)
	if err != nil {
		return fmt.Errorf("reading plugin: %w", err)
	}
	
	// Compute checksum
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])
	
	// Sign the checksum (not the full content - more efficient)
	signature, err := s.key.Sign(hash[:])
	if err != nil {
		return fmt.Errorf("signing: %w", err)
	}
	
	// Create signature structure
	sig := Signature{
		Version:   SignatureVersion,
		KeyID:     s.key.ID,
		Algorithm: "ed25519",
		Checksum:  checksum,
		Signature: base64.StdEncoding.EncodeToString(signature),
		Timestamp: time.Now().UTC(),
		Comment:   comment,
	}
	
	// Write signature file
	sigPath := pluginPath + SignatureExtension
	sigContent := formatSignature(sig)
	if err := os.WriteFile(sigPath, []byte(sigContent), 0644); err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}
	
	// Write checksum file (human-readable)
	sumPath := pluginPath + ChecksumExtension
	sumContent := fmt.Sprintf("%s  %s\n", checksum, filepath.Base(pluginPath))
	if err := os.WriteFile(sumPath, []byte(sumContent), 0644); err != nil {
		return fmt.Errorf("writing checksum: %w", err)
	}
	
	return nil
}

// formatSignature formats a signature for file storage.
func formatSignature(sig Signature) string {
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN Q PLUGIN SIGNATURE-----\n")
	buf.WriteString(fmt.Sprintf("Version: %d\n", sig.Version))
	buf.WriteString(fmt.Sprintf("KeyID: %s\n", sig.KeyID))
	buf.WriteString(fmt.Sprintf("Algorithm: %s\n", sig.Algorithm))
	buf.WriteString(fmt.Sprintf("Checksum: %s\n", sig.Checksum))
	buf.WriteString(fmt.Sprintf("Timestamp: %s\n", sig.Timestamp.Format(time.RFC3339)))
	if sig.Comment != "" {
		buf.WriteString(fmt.Sprintf("Comment: %s\n", sig.Comment))
	}
	buf.WriteString("\n")
	buf.WriteString(sig.Signature)
	buf.WriteString("\n-----END Q PLUGIN SIGNATURE-----\n")
	return buf.String()
}

// Verifier handles plugin verification.
type Verifier struct {
	trustedKeys *TrustedKeys
	strict      bool // If true, reject plugins without signatures
}

// NewVerifier creates a new verifier with trusted keys.
func NewVerifier(trustedKeys *TrustedKeys, strict bool) *Verifier {
	return &Verifier{
		trustedKeys: trustedKeys,
		strict:      strict,
	}
}

// VerifyFile verifies a plugin file against its signature.
func (v *Verifier) VerifyFile(pluginPath string) (*VerificationResult, error) {
	result := &VerificationResult{
		PluginPath: pluginPath,
		Verified:   false,
	}
	
	// Read plugin content
	content, err := os.ReadFile(pluginPath)
	if err != nil {
		return result, fmt.Errorf("reading plugin: %w", err)
	}
	
	// Compute checksum
	hash := sha256.Sum256(content)
	result.Checksum = hex.EncodeToString(hash[:])
	
	// Read signature file
	sigPath := pluginPath + SignatureExtension
	sigContent, err := os.ReadFile(sigPath)
	if err != nil {
		if os.IsNotExist(err) {
			result.Error = ErrSignatureMissing.Error()
			if v.strict {
				return result, ErrSignatureMissing
			}
			return result, nil
		}
		return result, fmt.Errorf("reading signature: %w", err)
	}
	
	// Parse signature
	sig, err := parseSignature(string(sigContent))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.KeyID = sig.KeyID
	result.Timestamp = sig.Timestamp
	result.Comment = sig.Comment
	
	// Verify checksum matches
	if sig.Checksum != result.Checksum {
		result.Error = ErrChecksumMismatch.Error()
		return result, ErrChecksumMismatch
	}
	
	// Get signing key
	key, trusted := v.trustedKeys.Get(sig.KeyID)
	if !trusted {
		result.Error = ErrKeyNotTrusted.Error()
		return result, ErrKeyNotTrusted
	}
	result.KeyTrusted = true
	result.KeyComment = key.Comment
	
	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		result.Error = "invalid signature encoding"
		return result, ErrInvalidSignature
	}
	
	// Verify signature
	if !key.Verify(hash[:], sigBytes) {
		result.Error = ErrSignatureInvalid.Error()
		return result, ErrSignatureInvalid
	}
	
	result.Verified = true
	return result, nil
}

// VerificationResult contains the result of plugin verification.
type VerificationResult struct {
	PluginPath string    `json:"pluginPath"`
	Verified   bool      `json:"verified"`
	Checksum   string    `json:"checksum"`
	KeyID      string    `json:"keyId,omitempty"`
	KeyTrusted bool      `json:"keyTrusted"`
	KeyComment string    `json:"keyComment,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
	Comment    string    `json:"comment,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// parseSignature parses a signature file.
func parseSignature(content string) (*Signature, error) {
	sig := &Signature{}
	
	lines := strings.Split(content, "\n")
	inBody := false
	var sigLines []string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if line == "-----BEGIN Q PLUGIN SIGNATURE-----" {
			continue
		}
		if line == "-----END Q PLUGIN SIGNATURE-----" {
			break
		}
		if line == "" {
			inBody = true
			continue
		}
		
		if inBody {
			sigLines = append(sigLines, line)
		} else {
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) != 2 {
				continue
			}
			
			key, value := parts[0], parts[1]
			switch key {
			case "Version":
				fmt.Sscanf(value, "%d", &sig.Version)
			case "KeyID":
				sig.KeyID = value
			case "Algorithm":
				sig.Algorithm = value
			case "Checksum":
				sig.Checksum = value
			case "Timestamp":
				sig.Timestamp, _ = time.Parse(time.RFC3339, value)
			case "Comment":
				sig.Comment = value
			}
		}
	}
	
	sig.Signature = strings.Join(sigLines, "")
	
	if sig.KeyID == "" || sig.Checksum == "" || sig.Signature == "" {
		return nil, ErrInvalidSignature
	}
	
	return sig, nil
}

// LoadTrustedKeysFromFile loads trusted keys from a file.
// Format: one key per line, base64-encoded public key followed by optional comment
// Example:
//   MCowBQYDK2VwAyEA... Production Signing Key
//   MCowBQYDK2VwAyEA... Development Signing Key
func LoadTrustedKeysFromFile(path string) (*TrustedKeys, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	tk := NewTrustedKeys()
	
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, " ", 2)
		encoded := parts[0]
		comment := ""
		if len(parts) > 1 {
			comment = parts[1]
		}
		
		if err := tk.AddFromBase64(encoded, comment); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	
	return tk, nil
}

// SaveTrustedKeysToFile saves trusted keys to a file.
func SaveTrustedKeysToFile(tk *TrustedKeys, path string) error {
	var buf bytes.Buffer
	buf.WriteString("# Q Plugin Trusted Keys\n")
	buf.WriteString("# Format: <base64-public-key> <comment>\n")
	buf.WriteString(fmt.Sprintf("# Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	
	for _, key := range tk.List() {
		buf.WriteString(key.EncodePublic())
		if key.Comment != "" {
			buf.WriteString(" ")
			buf.WriteString(key.Comment)
		}
		buf.WriteString("\n")
	}
	
	return os.WriteFile(path, buf.Bytes(), 0644)
}

// SaveKeyPair saves a key pair to files.
func SaveKeyPair(key *SigningKey, basePath string) error {
	// Save public key
	pubPath := basePath + ".pub"
	pubContent := fmt.Sprintf("# Q Plugin Signing Key (Public)\n# ID: %s\n# Created: %s\n# %s\n%s\n",
		key.ID, key.Created.Format(time.RFC3339), key.Comment, key.EncodePublic())
	if err := os.WriteFile(pubPath, []byte(pubContent), 0644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}
	
	// Save private key (with restricted permissions)
	if key.Private != nil {
		privPath := basePath + ".key"
		privContent := fmt.Sprintf("# Q Plugin Signing Key (Private) - KEEP SECRET!\n# ID: %s\n# Created: %s\n# %s\n%s\n",
			key.ID, key.Created.Format(time.RFC3339), key.Comment, key.EncodePrivate())
		if err := os.WriteFile(privPath, []byte(privContent), 0600); err != nil {
			return fmt.Errorf("writing private key: %w", err)
		}
	}
	
	return nil
}

// LoadPrivateKey loads a private key from a file.
func LoadPrivateKey(path string) (*SigningKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return ParsePrivateKey(line)
	}
	
	return nil, ErrInvalidKeyFormat
}

// StreamVerify verifies a plugin by streaming (for large files).
func (v *Verifier) StreamVerify(pluginPath string) (*VerificationResult, error) {
	result := &VerificationResult{
		PluginPath: pluginPath,
		Verified:   false,
	}
	
	// Open plugin file
	f, err := os.Open(pluginPath)
	if err != nil {
		return result, fmt.Errorf("opening plugin: %w", err)
	}
	defer f.Close()
	
	// Compute checksum by streaming
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return result, fmt.Errorf("reading plugin: %w", err)
	}
	hash := h.Sum(nil)
	result.Checksum = hex.EncodeToString(hash)
	
	// Read and parse signature file
	sigPath := pluginPath + SignatureExtension
	sigContent, err := os.ReadFile(sigPath)
	if err != nil {
		if os.IsNotExist(err) {
			result.Error = ErrSignatureMissing.Error()
			if v.strict {
				return result, ErrSignatureMissing
			}
			return result, nil
		}
		return result, fmt.Errorf("reading signature: %w", err)
	}
	
	sig, err := parseSignature(string(sigContent))
	if err != nil {
		result.Error = err.Error()
		return result, err
	}
	result.KeyID = sig.KeyID
	result.Timestamp = sig.Timestamp
	
	// Verify checksum
	if sig.Checksum != result.Checksum {
		result.Error = ErrChecksumMismatch.Error()
		return result, ErrChecksumMismatch
	}
	
	// Get and verify with trusted key
	key, trusted := v.trustedKeys.Get(sig.KeyID)
	if !trusted {
		result.Error = ErrKeyNotTrusted.Error()
		return result, ErrKeyNotTrusted
	}
	result.KeyTrusted = true
	result.KeyComment = key.Comment
	
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		result.Error = "invalid signature encoding"
		return result, ErrInvalidSignature
	}
	
	if !key.Verify(hash, sigBytes) {
		result.Error = ErrSignatureInvalid.Error()
		return result, ErrSignatureInvalid
	}
	
	result.Verified = true
	return result, nil
}
