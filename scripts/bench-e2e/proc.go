package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Server is one running policy server under test.
type Server struct {
	Kind     string // "garmr" or "opa"
	EvalURL  string
	ReadyURL string
	base     string
	cmd      *exec.Cmd
	exited   chan struct{}
	logPath  string
	// PolicyDir is the directory the server loaded from.
	PolicyDir string
}

type ServerOpts struct {
	Kind      string
	Bin       string
	PolicyDir string
	Port      int
	CPUs      string // taskset list, e.g. "0-3"; "" disables pinning
	Procs     int    // GOMAXPROCS; 0 leaves it unset
	// Audit turns on Garmr's file audit log / OPA's console decision log.
	Audit   bool
	WorkDir string
}

// startServer launches a server and waits until it reports ready, returning
// the time from exec to the first ready response.
func startServer(o ServerOpts) (*Server, time.Duration, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", o.Port)
	s := &Server{Kind: o.Kind, base: "http://" + addr, PolicyDir: o.PolicyDir, exited: make(chan struct{})}
	var args []string
	switch o.Kind {
	case "garmr":
		auditPath := filepath.Join(o.WorkDir, "garmr-audit.log")
		_ = os.Remove(auditPath)
		args = []string{o.Bin,
			"--http-addr", addr,
			"--policy-dir", o.PolicyDir,
			"--log-level", "error",
			"--rate-limit=false",
			"--audit=" + strconv.FormatBool(o.Audit),
			"--audit-path", auditPath,
		}
		s.EvalURL = s.base + "/v1/evaluate"
		s.ReadyURL = s.base + "/ready"
	case "opa":
		args = []string{o.Bin, "run", "--server",
			"--addr", addr,
			"--log-level", "error",
			"--disable-telemetry",
		}
		if o.Audit {
			args = append(args, "--set", "decision_logs.console=true")
		}
		args = append(args, o.PolicyDir)
		s.EvalURL = s.base + "/v1/data/bench/deny"
		s.ReadyURL = s.base + "/health"
	default:
		return nil, 0, fmt.Errorf("unknown server kind %q", o.Kind)
	}
	if o.CPUs != "" {
		args = append([]string{"taskset", "-c", o.CPUs}, args...)
	}

	s.logPath = filepath.Join(o.WorkDir, o.Kind+".log")
	logf, err := os.Create(s.logPath)
	if err != nil {
		return nil, 0, err
	}
	s.cmd = exec.Command(args[0], args[1:]...)
	s.cmd.Stdout, s.cmd.Stderr = logf, logf
	s.cmd.Env = os.Environ()
	if o.Procs > 0 {
		s.cmd.Env = append(s.cmd.Env, fmt.Sprintf("GOMAXPROCS=%d", o.Procs))
	}

	start := time.Now()
	if err := s.cmd.Start(); err != nil {
		logf.Close()
		return nil, 0, err
	}
	go func() { _ = s.cmd.Wait(); logf.Close(); close(s.exited) }()

	client := &http.Client{Timeout: time.Second}
	deadline := start.Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-s.exited:
			return nil, 0, fmt.Errorf("%s exited during startup; log:\n%s", o.Kind, tail(s.logPath))
		default:
		}
		resp, err := client.Get(s.ReadyURL)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s, time.Since(start), nil
			}
		}
		time.Sleep(time.Millisecond)
	}
	s.Stop()
	return nil, 0, fmt.Errorf("%s not ready after 5m", o.Kind)
}

func (s *Server) Pid() int { return s.cmd.Process.Pid }

func (s *Server) Stop() {
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.exited
	}
}

// Reload swaps the policy set through each server's own API: Garmr re-reads
// its policy dir, OPA replaces one module. file is relative to PolicyDir and
// has already been rewritten on disk.
func (s *Server) Reload(ctx context.Context, file string) error {
	var req *http.Request
	var err error
	switch s.Kind {
	case "garmr":
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/v1/policies/reload", nil)
	case "opa":
		var src []byte
		path := filepath.Join(s.PolicyDir, file)
		if src, err = os.ReadFile(path); err != nil {
			return err
		}
		// Modules loaded from disk are keyed by their path, without the
		// leading slash.
		id := strings.TrimPrefix(path, "/")
		req, err = http.NewRequestWithContext(ctx, http.MethodPut, s.base+"/v1/policies/"+id, bytes.NewReader(src))
	}
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("reload: %s: %.300s", resp.Status, b)
	}
	return nil
}

// cpuTime is the process's user+system CPU time.
func cpuTime(pid int) (time.Duration, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Fields after the parenthesised comm; utime and stime are fields 14
	// and 15 overall, i.e. 12 and 13 after it.
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+2:]))
	ut, _ := strconv.ParseInt(f[11], 10, 64)
	st, _ := strconv.ParseInt(f[12], 10, 64)
	const clkTck = 100 // USER_HZ on Linux
	return time.Duration(ut+st) * time.Second / clkTck, nil
}

// memKB returns VmRSS and VmHWM (peak RSS) in KiB.
func memKB(pid int) (rss, hwm int64) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "VmRSS:":
			rss = v
		case "VmHWM:":
			hwm = v
		}
	}
	return rss, hwm
}

func tail(path string) string {
	b, _ := os.ReadFile(path)
	if len(b) > 2000 {
		b = b[len(b)-2000:]
	}
	return string(b)
}
