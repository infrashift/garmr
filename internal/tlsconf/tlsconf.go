// internal/tlsconf/tlsconf.go
// Package tlsconf builds the server's optional TLS configuration and keeps it
// current as certificate files rotate on disk.
//
// TLS is opt-in. Inside a service mesh (Consul Connect) the sidecar owns mTLS
// and Garmr serves plain HTTP; this package exists for deployments outside a
// mesh, where Garmr terminates TLS itself.
//
// Two choices here are load-bearing:
//
//   - Client certificates are requested with VerifyClientCertIfGiven, not
//     RequireAndVerifyClientCert. Orchestrator probes (kubelet, Consul HTTPS
//     checks) present no client certificate; requiring one at the handshake
//     would fail every probe and pull the instance from service. A presented
//     certificate is still fully verified at the handshake, and the server's
//     auth middleware rejects non-probe requests that carry no verified chain.
//
//   - Rotation is detected by polling file stamps, not fsnotify. Template
//     renderers (Nomad, Vault Agent, cert-manager volume updates) replace files
//     by atomic rename or symlink swap, which inotify watches handle poorly.
package tlsconf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// DefaultReloadInterval is how often certificate files are checked for
// changes when Options.ReloadInterval is unset.
const DefaultReloadInterval = time.Minute

// Options configures server-side TLS.
type Options struct {
	// CertFile and KeyFile are the PEM server certificate (optionally a full
	// chain) and its private key. Both are required.
	CertFile string
	KeyFile  string
	// ClientCAFile, when set, enables mTLS: presented client certificates
	// must chain to a CA in this PEM bundle.
	ClientCAFile string
	// MinVersion is "1.2" (default) or "1.3".
	MinVersion string
	// ReloadInterval is how often the files are checked for changes
	// (default DefaultReloadInterval).
	ReloadInterval time.Duration
}

// ParseMinVersion maps a configured minimum version to its tls constant.
func ParseMinVersion(v string) (uint16, error) {
	switch v {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("invalid TLS min version %q: want 1.2 or 1.3", v)
	}
}

// fileStamp identifies one observed version of a file.
type fileStamp struct {
	modTime time.Time
	size    int64
}

// snapshot is one loaded, internally consistent set of TLS material.
type snapshot struct {
	config *tls.Config
	leaf   *x509.Certificate
	stamps []fileStamp
}

// Reloader serves the current TLS configuration and swaps it when the
// underlying files change.
type Reloader struct {
	opts       Options
	minVersion uint16
	logger     *zap.Logger
	current    atomic.Pointer[snapshot]
	// lastFailed records the stamps of the last set that failed to load, so a
	// broken rotation is reported once rather than on every tick.
	lastFailed []fileStamp
}

// New validates opts and loads the TLS material eagerly, so a bad
// certificate fails startup rather than the first handshake.
func New(opts Options, logger *zap.Logger) (*Reloader, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, errors.New("TLS enabled but cert file and key file are both required")
	}
	minVersion, err := ParseMinVersion(opts.MinVersion)
	if err != nil {
		return nil, err
	}
	if opts.ReloadInterval <= 0 {
		opts.ReloadInterval = DefaultReloadInterval
	}

	r := &Reloader{opts: opts, minVersion: minVersion, logger: logger}
	snap, err := r.load()
	if err != nil {
		return nil, err
	}
	r.current.Store(snap)
	r.logLoaded("loaded TLS certificate", snap)
	return r, nil
}

// MutualTLS reports whether client certificates are verified (a client CA
// is configured).
func (r *Reloader) MutualTLS() bool {
	return r.opts.ClientCAFile != ""
}

// TLSConfig returns the config to install on the http.Server. Every
// handshake is served from the current snapshot, so certificate and client
// CA rotate together and without a restart.
func (r *Reloader) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: r.minVersion,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return r.current.Load().config, nil
		},
	}
}

// Leaf returns the currently served leaf certificate.
func (r *Reloader) Leaf() *x509.Certificate {
	return r.current.Load().leaf
}

// Run polls the files every ReloadInterval until ctx is done.
func (r *Reloader) Run(ctx context.Context) {
	ticker := time.NewTicker(r.opts.ReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Reload()
		}
	}
}

// Reload swaps in new TLS material if any file changed since the last load.
// On failure the previous snapshot keeps serving: a rotation caught half
// written (new certificate, old key) fails to pair here and succeeds on a
// later check once both files are in place. It reports whether a new
// snapshot was installed.
func (r *Reloader) Reload() bool {
	stamps, err := r.stat()
	if err == nil && (stampsEqual(stamps, r.current.Load().stamps) || stampsEqual(stamps, r.lastFailed)) {
		return false
	}

	snap, err := r.load()
	if err != nil {
		r.logger.Warn("TLS reload failed; still serving the previous certificate", zap.Error(err))
		r.lastFailed = stamps
		return false
	}
	r.lastFailed = nil
	r.current.Store(snap)
	r.logLoaded("reloaded TLS certificate", snap)
	return true
}

func (r *Reloader) files() []string {
	files := []string{r.opts.CertFile, r.opts.KeyFile}
	if r.opts.ClientCAFile != "" {
		files = append(files, r.opts.ClientCAFile)
	}
	return files
}

func (r *Reloader) stat() ([]fileStamp, error) {
	files := r.files()
	stamps := make([]fileStamp, len(files))
	for i, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		stamps[i] = fileStamp{modTime: fi.ModTime(), size: fi.Size()}
	}
	return stamps, nil
}

// load reads every file and builds a snapshot. Stamps are taken before the
// reads, so a write racing the load is seen as a change on the next check.
func (r *Reloader) load() (*snapshot, error) {
	stamps, err := r.stat()
	if err != nil {
		return nil, fmt.Errorf("reading TLS files: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(r.opts.CertFile, r.opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS key pair: %w", err)
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("parsing TLS certificate: %w", err)
		}
	}

	cfg := &tls.Config{
		MinVersion:   r.minVersion,
		Certificates: []tls.Certificate{cert},
		// GetConfigForClient replaces the server's config wholesale, so
		// ALPN must be restated here or HTTP/2 is never negotiated.
		NextProtos: []string{"h2", "http/1.1"},
	}

	if r.opts.ClientCAFile != "" {
		pem, err := os.ReadFile(r.opts.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading TLS client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("TLS client CA file %s contains no PEM certificates", r.opts.ClientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return &snapshot{config: cfg, leaf: leaf, stamps: stamps}, nil
}

func (r *Reloader) logLoaded(msg string, snap *snapshot) {
	fields := []zap.Field{
		zap.String("subject", snap.leaf.Subject.String()),
		zap.String("serial", snap.leaf.SerialNumber.String()),
		zap.Time("not_after", snap.leaf.NotAfter),
		zap.Bool("mutual_tls", r.MutualTLS()),
	}
	if time.Now().After(snap.leaf.NotAfter) {
		r.logger.Warn(msg+" (EXPIRED)", fields...)
		return
	}
	r.logger.Info(msg, fields...)
}

func stampsEqual(a, b []fileStamp) bool {
	if len(a) != len(b) || a == nil {
		return false
	}
	for i := range a {
		if !a[i].modTime.Equal(b[i].modTime) || a[i].size != b[i].size {
			return false
		}
	}
	return true
}

// PeerIdentity returns the caller identity from a verified client
// certificate: the first spiffe:// URI SAN of the leaf, else its first URI
// SAN, else "". Only VerifiedChains is consulted — an unverified certificate
// never yields an identity.
func PeerIdentity(cs *tls.ConnectionState) string {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return ""
	}
	leaf := cs.VerifiedChains[0][0]
	for _, u := range leaf.URIs {
		if u.Scheme == "spiffe" {
			return u.String()
		}
	}
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String()
	}
	return ""
}

// HasVerifiedPeer reports whether the connection presented a client
// certificate that verified against the configured client CA.
func HasVerifiedPeer(cs *tls.ConnectionState) bool {
	return cs != nil && len(cs.VerifiedChains) > 0
}
