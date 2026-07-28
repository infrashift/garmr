package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestProbes_ConcurrentWithMarkReady covers the map race in handleReady.
//
// handleReady used to copy the s.checks map *reference* under RLock and then
// JSON-encode it after releasing the lock, while Start/MarkReady/Stop wrote
// the same map. That is an unrecoverable "concurrent map read and map write"
// fatal error — recoveryMiddleware cannot catch it, so the process dies.
//
// Under -race (which CI runs) this fails without the maps.Clone fix.
func TestProbes_ConcurrentWithMarkReady(t *testing.T) {
	srv := newMetricsTestServer(t)
	handler := srv.Handler()

	for _, path := range []string{"/ready", "/health"} {
		t.Run(path, func(t *testing.T) {
			var wg sync.WaitGroup
			stop := make(chan struct{})

			// Writers mutate s.checks and s.ready.
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
							srv.MarkReady()
						}
					}
				}()
			}

			// Readers serialise the same state.
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 200; j++ {
						req := httptest.NewRequest(http.MethodGet, path, nil)
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, req)
						if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
							t.Errorf("unexpected status %d from %s", rec.Code, path)
							return
						}
					}
				}()
			}

			// Readers finish on their own; then release the writers.
			readersDone := make(chan struct{})
			go func() {
				defer close(readersDone)
				for j := 0; j < 200; j++ {
					req := httptest.NewRequest(http.MethodGet, path, nil)
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
				}
			}()

			<-readersDone
			close(stop)
			wg.Wait()
		})
	}
}
