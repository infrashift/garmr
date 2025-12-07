// internal/plugin/signing_test.go
// Package plugin provides comprehensive tests for the plugin signing system.
package plugin

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ============================================
// KEY GENERATION TESTS
// ============================================

func TestGenerateKey(t *testing.T) {
	t.Run("generates valid Ed25519 key pair", func(t *testing.T) {
		key, err := GenerateKey("test key")
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		// Verify key components
		if key.Public == nil {
			t.Error("public key is nil")
		}
		if key.Private == nil {
			t.Error("private key is nil")
		}
		if len(key.Public) != ed25519.PublicKeySize {
			t.Errorf("public key wrong size: got %d, want %d", len(key.Public), ed25519.PublicKeySize)
		}
		if len(key.Private) != ed25519.PrivateKeySize {
			t.Errorf("private key wrong size: got %d, want %d", len(key.Private), ed25519.PrivateKeySize)
		}

		// Verify key ID is computed
		if key.ID == "" {
			t.Error("key ID is empty")
		}
		if len(key.ID) != KeyIDLength*2 { // hex encoded
			t.Errorf("key ID wrong length: got %d, want %d", len(key.ID), KeyIDLength*2)
		}

		// Verify comment is set
		if key.Comment != "test key" {
			t.Errorf("comment mismatch: got %q, want %q", key.Comment, "test key")
		}

		// Verify created timestamp is recent
		if time.Since(key.Created) > time.Minute {
			t.Error("created timestamp not set correctly")
		}
	})

	t.Run("generates unique keys", func(t *testing.T) {
		key1, _ := GenerateKey("key1")
		key2, _ := GenerateKey("key2")

		if key1.ID == key2.ID {
			t.Error("generated keys have same ID")
		}
		if key1.EncodePublic() == key2.EncodePublic() {
			t.Error("generated keys have same public key")
		}
	})
}

func TestKeyEncoding(t *testing.T) {
	key, _ := GenerateKey("test")

	t.Run("public key round-trip", func(t *testing.T) {
		encoded := key.EncodePublic()
		parsed, err := ParsePublicKey(encoded)
		if err != nil {
			t.Fatalf("ParsePublicKey failed: %v", err)
		}

		if parsed.ID != key.ID {
			t.Errorf("key ID mismatch: got %s, want %s", parsed.ID, key.ID)
		}
		if parsed.EncodePublic() != encoded {
			t.Error("public key encoding mismatch after round-trip")
		}
	})

	t.Run("private key round-trip", func(t *testing.T) {
		encoded := key.EncodePrivate()
		parsed, err := ParsePrivateKey(encoded)
		if err != nil {
			t.Fatalf("ParsePrivateKey failed: %v", err)
		}

		if parsed.ID != key.ID {
			t.Errorf("key ID mismatch: got %s, want %s", parsed.ID, key.ID)
		}
		if parsed.EncodePrivate() != encoded {
			t.Error("private key encoding mismatch after round-trip")
		}
	})

	t.Run("rejects invalid public key", func(t *testing.T) {
		_, err := ParsePublicKey("not-valid-base64!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}

		_, err = ParsePublicKey(base64.StdEncoding.EncodeToString([]byte("too short")))
		if err == nil {
			t.Error("expected error for wrong key size")
		}
	})

	t.Run("rejects invalid private key", func(t *testing.T) {
		_, err := ParsePrivateKey("not-valid-base64!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}

		_, err = ParsePrivateKey(base64.StdEncoding.EncodeToString([]byte("too short")))
		if err == nil {
			t.Error("expected error for wrong key size")
		}
	})
}

// ============================================
// SIGNING TESTS
// ============================================

func TestSignAndVerify(t *testing.T) {
	key, _ := GenerateKey("test signing key")

	t.Run("sign and verify data", func(t *testing.T) {
		data := []byte("test data to sign")

		signature, err := key.Sign(data)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}

		if len(signature) != ed25519.SignatureSize {
			t.Errorf("signature wrong size: got %d, want %d", len(signature), ed25519.SignatureSize)
		}

		if !key.Verify(data, signature) {
			t.Error("verification failed for valid signature")
		}
	})

	t.Run("verification fails for tampered data", func(t *testing.T) {
		data := []byte("original data")
		signature, _ := key.Sign(data)

		tamperedData := []byte("tampered data")
		if key.Verify(tamperedData, signature) {
			t.Error("verification should fail for tampered data")
		}
	})

	t.Run("verification fails for tampered signature", func(t *testing.T) {
		data := []byte("test data")
		signature, _ := key.Sign(data)

		// Tamper with signature
		signature[0] ^= 0xFF

		if key.Verify(data, signature) {
			t.Error("verification should fail for tampered signature")
		}
	})

	t.Run("verification fails with wrong key", func(t *testing.T) {
		data := []byte("test data")
		signature, _ := key.Sign(data)

		otherKey, _ := GenerateKey("other key")
		if otherKey.Verify(data, signature) {
			t.Error("verification should fail with different key")
		}
	})

	t.Run("sign requires private key", func(t *testing.T) {
		publicOnly, _ := ParsePublicKey(key.EncodePublic())

		_, err := publicOnly.Sign([]byte("data"))
		if err == nil {
			t.Error("Sign should fail without private key")
		}
	})
}

// ============================================
// FILE SIGNING TESTS
// ============================================

func TestSignerAndVerifier(t *testing.T) {
	// Setup: create temp directory and test file
	tmpDir := t.TempDir()
	pluginPath := filepath.Join(tmpDir, "test.so")
	pluginContent := []byte("fake plugin content for testing")
	if err := os.WriteFile(pluginPath, pluginContent, 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Generate signing key
	signingKey, _ := GenerateKey("test signer")

	// Setup trusted keys
	trustedKeys := NewTrustedKeys()
	trustedKeys.Add(signingKey)

	t.Run("sign and verify file - success", func(t *testing.T) {
		signer, err := NewSigner(signingKey)
		if err != nil {
			t.Fatalf("NewSigner failed: %v", err)
		}

		err = signer.SignFile(pluginPath, "test plugin v1.0")
		if err != nil {
			t.Fatalf("SignFile failed: %v", err)
		}

		// Verify signature file exists
		sigPath := pluginPath + SignatureExtension
		if _, err := os.Stat(sigPath); os.IsNotExist(err) {
			t.Error("signature file not created")
		}

		// Verify checksum file exists
		sumPath := pluginPath + ChecksumExtension
		if _, err := os.Stat(sumPath); os.IsNotExist(err) {
			t.Error("checksum file not created")
		}

		// Verify the signature
		verifier := NewVerifier(trustedKeys, true)
		result, err := verifier.VerifyFile(pluginPath)
		if err != nil {
			t.Fatalf("VerifyFile failed: %v", err)
		}

		if !result.Verified {
			t.Error("verification should succeed")
		}
		if result.KeyID != signingKey.ID {
			t.Errorf("key ID mismatch: got %s, want %s", result.KeyID, signingKey.ID)
		}
		if !result.KeyTrusted {
			t.Error("key should be trusted")
		}
		if result.Comment != "test plugin v1.0" {
			t.Errorf("comment mismatch: got %q", result.Comment)
		}
	})

	t.Run("verification fails for tampered plugin", func(t *testing.T) {
		// Sign the plugin
		signer, _ := NewSigner(signingKey)
		signer.SignFile(pluginPath, "test")

		// Tamper with the plugin
		tampered := append(pluginContent, []byte("tampered")...)
		os.WriteFile(pluginPath, tampered, 0644)

		// Verification should fail
		verifier := NewVerifier(trustedKeys, true)
		_, err := verifier.VerifyFile(pluginPath)
		if err == nil {
			t.Error("verification should fail for tampered plugin")
		}
		if err != ErrChecksumMismatch {
			t.Errorf("expected ErrChecksumMismatch, got: %v", err)
		}

		// Restore original content
		os.WriteFile(pluginPath, pluginContent, 0644)
	})

	t.Run("verification fails for tampered signature", func(t *testing.T) {
		// Sign the plugin
		signer, _ := NewSigner(signingKey)
		signer.SignFile(pluginPath, "test")

		// Tamper with signature file
		sigPath := pluginPath + SignatureExtension
		sigContent, _ := os.ReadFile(sigPath)
		// Corrupt the signature
		tampered := append(sigContent[:len(sigContent)-10], []byte("corrupted!")...)
		os.WriteFile(sigPath, tampered, 0644)

		// Verification should fail
		verifier := NewVerifier(trustedKeys, true)
		_, err := verifier.VerifyFile(pluginPath)
		if err == nil {
			t.Error("verification should fail for tampered signature")
		}
	})

	t.Run("verification fails for untrusted key", func(t *testing.T) {
		// Sign with a different key
		untrustedKey, _ := GenerateKey("untrusted")
		signer, _ := NewSigner(untrustedKey)
		signer.SignFile(pluginPath, "test")

		// Verify with original trusted keys (doesn't include untrustedKey)
		verifier := NewVerifier(trustedKeys, true)
		_, err := verifier.VerifyFile(pluginPath)
		if err == nil {
			t.Error("verification should fail for untrusted key")
		}
		if err != ErrKeyNotTrusted {
			t.Errorf("expected ErrKeyNotTrusted, got: %v", err)
		}
	})

	t.Run("verification fails for missing signature - strict mode", func(t *testing.T) {
		// Remove signature file
		os.Remove(pluginPath + SignatureExtension)

		// Strict verifier should fail
		verifier := NewVerifier(trustedKeys, true) // strict=true
		_, err := verifier.VerifyFile(pluginPath)
		if err == nil {
			t.Error("strict verification should fail for missing signature")
		}
		if err != ErrSignatureMissing {
			t.Errorf("expected ErrSignatureMissing, got: %v", err)
		}
	})

	t.Run("verification succeeds for missing signature - non-strict mode", func(t *testing.T) {
		// Remove signature file
		os.Remove(pluginPath + SignatureExtension)

		// Non-strict verifier should succeed (but mark as unverified)
		verifier := NewVerifier(trustedKeys, false) // strict=false
		result, err := verifier.VerifyFile(pluginPath)
		if err != nil {
			t.Fatalf("non-strict verification should not error: %v", err)
		}
		if result.Verified {
			t.Error("result should show as not verified")
		}
	})
}

// ============================================
// TRUSTED KEYS TESTS
// ============================================

func TestTrustedKeys(t *testing.T) {
	t.Run("add and retrieve keys", func(t *testing.T) {
		tk := NewTrustedKeys()
		key1, _ := GenerateKey("key1")
		key2, _ := GenerateKey("key2")

		tk.Add(key1)
		tk.Add(key2)

		retrieved, ok := tk.Get(key1.ID)
		if !ok {
			t.Error("failed to retrieve key1")
		}
		if retrieved.ID != key1.ID {
			t.Error("retrieved wrong key")
		}

		if !tk.IsTrusted(key1.ID) {
			t.Error("key1 should be trusted")
		}
		if !tk.IsTrusted(key2.ID) {
			t.Error("key2 should be trusted")
		}
		if tk.IsTrusted("unknown-key-id") {
			t.Error("unknown key should not be trusted")
		}
	})

	t.Run("add from base64", func(t *testing.T) {
		tk := NewTrustedKeys()
		key, _ := GenerateKey("test")

		err := tk.AddFromBase64(key.EncodePublic(), "test comment")
		if err != nil {
			t.Fatalf("AddFromBase64 failed: %v", err)
		}

		if !tk.IsTrusted(key.ID) {
			t.Error("key should be trusted after adding")
		}

		retrieved, _ := tk.Get(key.ID)
		if retrieved.Comment != "test comment" {
			t.Error("comment not set correctly")
		}
	})

	t.Run("reject invalid base64", func(t *testing.T) {
		tk := NewTrustedKeys()

		err := tk.AddFromBase64("not-valid-base64!", "test")
		if err == nil {
			t.Error("should reject invalid base64")
		}
	})

	t.Run("list all keys", func(t *testing.T) {
		tk := NewTrustedKeys()
		key1, _ := GenerateKey("key1")
		key2, _ := GenerateKey("key2")
		key3, _ := GenerateKey("key3")

		tk.Add(key1)
		tk.Add(key2)
		tk.Add(key3)

		list := tk.List()
		if len(list) != 3 {
			t.Errorf("expected 3 keys, got %d", len(list))
		}
	})
}

// ============================================
// FILE I/O TESTS
// ============================================

func TestKeyFileIO(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("save and load key pair", func(t *testing.T) {
		key, _ := GenerateKey("test key for file")
		basePath := filepath.Join(tmpDir, "test-key")

		err := SaveKeyPair(key, basePath)
		if err != nil {
			t.Fatalf("SaveKeyPair failed: %v", err)
		}

		// Check files exist
		pubPath := basePath + ".pub"
		privPath := basePath + ".key"

		if _, err := os.Stat(pubPath); os.IsNotExist(err) {
			t.Error("public key file not created")
		}
		if _, err := os.Stat(privPath); os.IsNotExist(err) {
			t.Error("private key file not created")
		}

		// Check private key permissions
		info, _ := os.Stat(privPath)
		if info.Mode().Perm() != 0600 {
			t.Errorf("private key wrong permissions: got %o, want 0600", info.Mode().Perm())
		}

		// Load private key back
		loaded, err := LoadPrivateKey(privPath)
		if err != nil {
			t.Fatalf("LoadPrivateKey failed: %v", err)
		}

		if loaded.ID != key.ID {
			t.Error("loaded key has different ID")
		}
		if loaded.EncodePrivate() != key.EncodePrivate() {
			t.Error("loaded key has different private key")
		}
	})

	t.Run("save and load trusted keys file", func(t *testing.T) {
		tk := NewTrustedKeys()
		key1, _ := GenerateKey("key1")
		key2, _ := GenerateKey("key2")
		key1.Comment = "First Key"
		key2.Comment = "Second Key"
		tk.Add(key1)
		tk.Add(key2)

		filePath := filepath.Join(tmpDir, "trusted-keys")
		err := SaveTrustedKeysToFile(tk, filePath)
		if err != nil {
			t.Fatalf("SaveTrustedKeysToFile failed: %v", err)
		}

		// Load back
		loaded, err := LoadTrustedKeysFromFile(filePath)
		if err != nil {
			t.Fatalf("LoadTrustedKeysFromFile failed: %v", err)
		}

		if !loaded.IsTrusted(key1.ID) {
			t.Error("key1 not in loaded keys")
		}
		if !loaded.IsTrusted(key2.ID) {
			t.Error("key2 not in loaded keys")
		}

		// Check comments preserved
		loadedKey1, _ := loaded.Get(key1.ID)
		if loadedKey1.Comment != "First Key" {
			t.Errorf("comment not preserved: got %q", loadedKey1.Comment)
		}
	})

	t.Run("load handles comments and blank lines", func(t *testing.T) {
		key, _ := GenerateKey("test")

		content := `# This is a comment
# Another comment

` + key.EncodePublic() + ` Test Key

# End of file
`
		filePath := filepath.Join(tmpDir, "keys-with-comments")
		os.WriteFile(filePath, []byte(content), 0644)

		loaded, err := LoadTrustedKeysFromFile(filePath)
		if err != nil {
			t.Fatalf("failed to load: %v", err)
		}

		if !loaded.IsTrusted(key.ID) {
			t.Error("key not loaded correctly")
		}
	})
}

// ============================================
// SIGNATURE PARSING TESTS
// ============================================

func TestSignatureParsing(t *testing.T) {
	t.Run("parse valid signature", func(t *testing.T) {
		content := `-----BEGIN Q PLUGIN SIGNATURE-----
Version: 1
KeyID: a1b2c3d4e5f6g7h8
Algorithm: ed25519
Checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Timestamp: 2024-12-06T15:30:00Z
Comment: Test Plugin v1.0

dGVzdHNpZ25hdHVyZQ==
-----END Q PLUGIN SIGNATURE-----
`
		sig, err := parseSignature(content)
		if err != nil {
			t.Fatalf("parseSignature failed: %v", err)
		}

		if sig.Version != 1 {
			t.Errorf("version: got %d, want 1", sig.Version)
		}
		if sig.KeyID != "a1b2c3d4e5f6g7h8" {
			t.Errorf("keyID: got %s", sig.KeyID)
		}
		if sig.Algorithm != "ed25519" {
			t.Errorf("algorithm: got %s", sig.Algorithm)
		}
		if sig.Comment != "Test Plugin v1.0" {
			t.Errorf("comment: got %s", sig.Comment)
		}
		if sig.Signature != "dGVzdHNpZ25hdHVyZQ==" {
			t.Errorf("signature: got %s", sig.Signature)
		}
	})

	t.Run("reject invalid signature format", func(t *testing.T) {
		invalidCases := []struct {
			name    string
			content string
		}{
			{"missing keyID", `-----BEGIN Q PLUGIN SIGNATURE-----
Checksum: abc123
dGVzdA==
-----END Q PLUGIN SIGNATURE-----`},
			{"missing checksum", `-----BEGIN Q PLUGIN SIGNATURE-----
KeyID: abc123
dGVzdA==
-----END Q PLUGIN SIGNATURE-----`},
			{"missing signature body", `-----BEGIN Q PLUGIN SIGNATURE-----
KeyID: abc123
Checksum: abc123
-----END Q PLUGIN SIGNATURE-----`},
		}

		for _, tc := range invalidCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := parseSignature(tc.content)
				if err == nil {
					t.Error("expected error for invalid signature")
				}
			})
		}
	})
}

// ============================================
// STREAM VERIFICATION TESTS
// ============================================

func TestStreamVerify(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a larger test file
	largeContent := make([]byte, 1024*1024) // 1MB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	pluginPath := filepath.Join(tmpDir, "large.so")
	os.WriteFile(pluginPath, largeContent, 0644)

	key, _ := GenerateKey("test")
	trustedKeys := NewTrustedKeys()
	trustedKeys.Add(key)

	signer, _ := NewSigner(key)
	signer.SignFile(pluginPath, "large plugin")

	t.Run("stream verify matches regular verify", func(t *testing.T) {
		verifier := NewVerifier(trustedKeys, true)

		regularResult, err := verifier.VerifyFile(pluginPath)
		if err != nil {
			t.Fatalf("VerifyFile failed: %v", err)
		}

		streamResult, err := verifier.StreamVerify(pluginPath)
		if err != nil {
			t.Fatalf("StreamVerify failed: %v", err)
		}

		if regularResult.Checksum != streamResult.Checksum {
			t.Error("checksums don't match")
		}
		if regularResult.Verified != streamResult.Verified {
			t.Error("verification results don't match")
		}
	})
}

// ============================================
// CHECKSUM TESTS
// ============================================

func TestChecksumComputation(t *testing.T) {
	t.Run("checksum matches expected SHA256", func(t *testing.T) {
		tmpDir := t.TempDir()
		content := []byte("test content for checksum")
		pluginPath := filepath.Join(tmpDir, "test.so")
		os.WriteFile(pluginPath, content, 0644)

		// Compute expected checksum
		hash := sha256.Sum256(content)
		expected := hex.EncodeToString(hash[:])

		// Sign and verify
		key, _ := GenerateKey("test")
		signer, _ := NewSigner(key)
		signer.SignFile(pluginPath, "test")

		trustedKeys := NewTrustedKeys()
		trustedKeys.Add(key)
		verifier := NewVerifier(trustedKeys, true)

		result, _ := verifier.VerifyFile(pluginPath)
		if result.Checksum != expected {
			t.Errorf("checksum mismatch: got %s, want %s", result.Checksum, expected)
		}
	})
}

// ============================================
// INTEGRATION TESTS
// ============================================

func TestFullSigningWorkflow(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Generate signing key
	signingKey, err := GenerateKey("Integration Test Signing Key")
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	// Step 2: Save key pair
	keyBasePath := filepath.Join(tmpDir, "signing-key")
	if err := SaveKeyPair(signingKey, keyBasePath); err != nil {
		t.Fatalf("saving key failed: %v", err)
	}

	// Step 3: Create "plugin" files
	plugins := map[string][]byte{
		"s3.so":     []byte("fake s3 plugin content"),
		"consul.so": []byte("fake consul plugin content"),
		"duckdb.so": []byte("fake duckdb plugin content"),
	}

	for name, content := range plugins {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, content, 0644); err != nil {
			t.Fatalf("creating %s failed: %v", name, err)
		}
	}

	// Step 4: Load private key and sign plugins
	loadedKey, err := LoadPrivateKey(keyBasePath + ".key")
	if err != nil {
		t.Fatalf("loading private key failed: %v", err)
	}

	signer, err := NewSigner(loadedKey)
	if err != nil {
		t.Fatalf("creating signer failed: %v", err)
	}

	for name := range plugins {
		path := filepath.Join(tmpDir, name)
		if err := signer.SignFile(path, name+" v1.0"); err != nil {
			t.Fatalf("signing %s failed: %v", name, err)
		}
	}

	// Step 5: Setup trusted keys (simulating Q installation)
	trustedKeysPath := filepath.Join(tmpDir, "trusted-keys")
	trustedKeys := NewTrustedKeys()
	trustedKeys.Add(signingKey)
	if err := SaveTrustedKeysToFile(trustedKeys, trustedKeysPath); err != nil {
		t.Fatalf("saving trusted keys failed: %v", err)
	}

	// Step 6: Load trusted keys (simulating Q startup)
	loadedTrustedKeys, err := LoadTrustedKeysFromFile(trustedKeysPath)
	if err != nil {
		t.Fatalf("loading trusted keys failed: %v", err)
	}

	// Step 7: Verify all plugins
	verifier := NewVerifier(loadedTrustedKeys, true)

	for name := range plugins {
		path := filepath.Join(tmpDir, name)
		result, err := verifier.VerifyFile(path)
		if err != nil {
			t.Errorf("verifying %s failed: %v", name, err)
			continue
		}
		if !result.Verified {
			t.Errorf("%s not verified", name)
		}
		if result.KeyID != signingKey.ID {
			t.Errorf("%s wrong key ID: got %s, want %s", name, result.KeyID, signingKey.ID)
		}
	}

	// Step 8: Tamper with one plugin and verify it fails
	tamperedPath := filepath.Join(tmpDir, "s3.so")
	os.WriteFile(tamperedPath, []byte("TAMPERED"), 0644)

	_, err = verifier.VerifyFile(tamperedPath)
	if err != ErrChecksumMismatch {
		t.Errorf("tampered plugin should fail with checksum mismatch, got: %v", err)
	}
}

// ============================================
// BENCHMARK TESTS
// ============================================

func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey("benchmark key")
	}
}

func BenchmarkSigning(b *testing.B) {
	key, _ := GenerateKey("benchmark")
	data := make([]byte, 1024) // 1KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Sign(data)
	}
}

func BenchmarkVerification(b *testing.B) {
	key, _ := GenerateKey("benchmark")
	data := make([]byte, 1024)
	signature, _ := key.Sign(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Verify(data, signature)
	}
}

func BenchmarkFileVerification(b *testing.B) {
	tmpDir := b.TempDir()

	// Create test file
	content := make([]byte, 10*1024*1024) // 10MB
	pluginPath := filepath.Join(tmpDir, "bench.so")
	os.WriteFile(pluginPath, content, 0644)

	// Sign it
	key, _ := GenerateKey("bench")
	signer, _ := NewSigner(key)
	signer.SignFile(pluginPath, "bench")

	// Setup verifier
	trustedKeys := NewTrustedKeys()
	trustedKeys.Add(key)
	verifier := NewVerifier(trustedKeys, true)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifier.StreamVerify(pluginPath)
	}
}
