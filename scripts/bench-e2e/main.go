// Command bench-e2e drives the real garmr-server and `opa run --server`
// binaries over HTTP with identical policies, inputs and load, verifying
// every scenario's decisions end to end before timing it.
//
//	scripts/bench-e2e/run.sh            # full run (~40 min)
//	scripts/bench-e2e/run.sh -quick     # smoke run (~3 min)
//
// Phases: verify (correctness + sequential latency), startup (time to ready
// and RSS by policy count), closed (max throughput by concurrency), open
// (latency at equal offered rates), soak, reload (policy swap under load).
// It is a separate module with no dependency on Garmr or OPA.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

type config struct {
	garmrBin, opaBin string
	work, out        string
	serverCPUs       string
	procs            int
	runs             int
	quick            bool
	phases           map[string]bool
	servers          []string
	warm, dur        time.Duration
}

// Results is everything a run measured; it is written as JSON and rendered
// to summary.md.
type Results struct {
	Started  time.Time         `json:"started"`
	Host     map[string]string `json:"host"`
	Verify   []VerifyResult    `json:"verify,omitempty"`
	Startup  []StartupResult   `json:"startup,omitempty"`
	Closed   []LoadResult      `json:"closed,omitempty"`
	Open     []LoadResult      `json:"open,omitempty"`
	Soak     []SoakResult      `json:"soak,omitempty"`
	Reload   []ReloadResult    `json:"reload,omitempty"`
	Failures []string          `json:"failures,omitempty"`
}

type VerifyResult struct {
	Server   string `json:"server"`
	Scenario string `json:"scenario"`
	Case     string `json:"case"`
	ReqBytes int    `json:"req_bytes"`
	Stats    Stats  `json:"stats"`
}

type StartupResult struct {
	Server   string  `json:"server"`
	Scenario string  `json:"scenario"`
	Policies int     `json:"policies"`
	ReadyMs  float64 `json:"ready_ms"` // median
	RSSMB    float64 `json:"rss_mb"`   // median, right after ready
	AllMs    []float64
}

type LoadResult struct {
	Server   string `json:"server"`
	Scenario string `json:"scenario"`
	Conns    int    `json:"conns,omitempty"`
	Rate     int    `json:"rate,omitempty"`
	Stats    Stats  `json:"stats"`
	RunsRPS  []float64
}

type SoakResult struct {
	Server  string  `json:"server"`
	Rate    int     `json:"rate"`
	Overall Stats   `json:"overall"`
	Windows []Stats `json:"windows"`
	RSSMB   []float64
}

type ReloadResult struct {
	Server   string  `json:"server"`
	Rate     int     `json:"rate"`
	CallMs   float64 `json:"reload_call_ms"`
	EffectMs float64 `json:"effect_ms"` // reload start -> first request seeing the new policy
	// Requests sent after the reload call returned that still saw the old
	// policy.
	StaleAfter int64 `json:"stale_after_return"`
	Before     Stats `json:"before"`
	During     Stats `json:"during"`
	After      Stats `json:"after"`
}

var ports = map[string]int{"garmr": 18080, "opa": 18181}

func main() {
	var c config
	var phases, servers string
	flag.StringVar(&c.garmrBin, "garmr", "../../bin/garmr-server", "garmr-server binary")
	flag.StringVar(&c.opaBin, "opa", "bin/opa", "opa binary")
	flag.StringVar(&c.work, "work", "work", "scratch dir for generated policies and logs")
	flag.StringVar(&c.out, "out", "results", "results dir")
	flag.StringVar(&c.serverCPUs, "server-cpus", "0-3", "CPUs the servers are pinned to (taskset list; empty disables)")
	flag.IntVar(&c.procs, "procs", 4, "server GOMAXPROCS (0 = unset)")
	flag.IntVar(&c.runs, "runs", 3, "closed-loop repetitions (median reported)")
	flag.BoolVar(&c.quick, "quick", false, "short smoke run")
	flag.StringVar(&phases, "phases", "verify,startup,closed,open,soak,reload", "phases to run")
	flag.StringVar(&servers, "servers", "garmr,opa", "servers to run")
	flag.Parse()

	c.phases = map[string]bool{}
	for _, p := range strings.Split(phases, ",") {
		c.phases[p] = true
	}
	c.servers = strings.Split(servers, ",")
	c.warm, c.dur = 2*time.Second, 10*time.Second
	if c.quick {
		c.warm, c.dur, c.runs = 500*time.Millisecond, 2*time.Second, 1
	}
	for _, p := range []*string{&c.garmrBin, &c.opaBin, &c.work, &c.out} {
		abs, err := filepath.Abs(*p)
		if err != nil {
			log.Fatal(err)
		}
		*p = abs
	}

	res := &Results{Started: time.Now(), Host: hostInfo(c)}
	run(c, res)

	dir := filepath.Join(c.out, res.Started.Format("20060102-150405"))
	if c.quick {
		dir += "-quick"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	j, _ := json.MarshalIndent(res, "", "  ")
	must(os.WriteFile(filepath.Join(dir, "results.json"), j, 0o644))
	md := render(res)
	must(os.WriteFile(filepath.Join(dir, "summary.md"), []byte(md), 0o644))
	fmt.Println(md)
	log.Printf("results written to %s", dir)
	if len(res.Failures) > 0 {
		os.Exit(1)
	}
}

func run(c config, res *Results) {
	inputSizes := []struct {
		label string
		size  int
	}{{"1KB", 1 << 10}, {"10KB", 10 << 10}, {"100KB", 100 << 10}, {"1MB", 1 << 20}, {"4MB", 4 << 20}}
	var sizeScenarios []*Scenario
	for _, s := range inputSizes {
		sizeScenarios = append(sizeScenarios, inputSizeScenario(s.label, s.size))
	}
	core := []*Scenario{simpleScenario(), manyScenario(500, true), manyScenario(500, false), forEachScenario()}

	if c.phases["verify"] {
		phase("verify")
		for _, sc := range append(slices.Clone(core), sizeScenarios...) {
			for _, kind := range c.servers {
				verify(c, res, sc, kind)
			}
		}
		if len(res.Failures) > 0 {
			log.Printf("verification failed; skipping timing phases")
			return
		}
	}

	if c.phases["startup"] {
		phase("startup")
		counts := []int{1, 10, 100, 500, 2000, 5000}
		if c.quick {
			counts = []int{1, 500}
		}
		var scs []*Scenario
		for _, n := range counts {
			scs = append(scs, manyScenario(n, true))
		}
		scs = append(scs, manyScenario(500, false))
		for _, sc := range scs {
			for _, kind := range c.servers {
				startup(c, res, sc, kind)
			}
		}
	}

	if c.phases["closed"] {
		phase("closed")
		conns := []int{1, 4, 16, 64, 256}
		if c.quick {
			conns = []int{1, 64}
		}
		for _, sc := range core {
			for _, kind := range c.servers {
				closed(c, res, sc, kind, conns)
			}
		}
		// Big bodies saturate 4 cores at low concurrency; more connections
		// only queue.
		for _, sc := range sizeScenarios {
			for _, kind := range c.servers {
				closed(c, res, sc, kind, []int{8})
			}
		}
	}

	// Equal offered load for both servers, plus fractions of each one's own
	// measured capacity on the simple scenario.
	maxRPS := map[string]float64{}
	for _, r := range res.Closed {
		if r.Scenario == "simple" && r.Stats.RPS > maxRPS[r.Server] {
			maxRPS[r.Server] = r.Stats.RPS
		}
	}
	slowest := 0.0
	for _, kind := range c.servers {
		if v := maxRPS[kind]; v > 0 && (slowest == 0 || v < slowest) {
			slowest = v
		}
	}
	if slowest == 0 {
		slowest = 10000
	}

	if c.phases["open"] {
		phase("open")
		rates := []int{1000, 5000, 10000, 20000, 40000, 80000}
		if c.quick {
			rates = []int{1000, 10000}
		}
		for _, kind := range c.servers {
			r := slices.Clone(rates)
			if m := maxRPS[kind]; m > 0 && !c.quick {
				r = append(r, int(0.5*m), int(0.75*m), int(0.9*m))
			}
			sort.Ints(r)
			open(c, res, simpleScenario(), kind, r)
		}
	}

	if c.phases["soak"] {
		phase("soak")
		rate, dur := int(0.5*slowest), 2*time.Minute
		if c.quick {
			dur = 6 * time.Second
		}
		for _, kind := range c.servers {
			soak(c, res, kind, rate, dur)
		}
	}

	if c.phases["reload"] {
		phase("reload")
		rate := int(0.25 * slowest)
		for _, kind := range c.servers {
			reload(c, res, kind, rate)
		}
	}
}

func phase(name string) { log.Printf("=== phase %s", name) }

// launch writes the scenario and starts one server on it.
func launch(c config, sc *Scenario, kind string, audit bool) (*Server, time.Duration, error) {
	garmrDir, opaDir, err := sc.write(c.work)
	if err != nil {
		return nil, 0, err
	}
	o := ServerOpts{Kind: kind, Port: ports[kind], CPUs: c.serverCPUs, Procs: c.procs, Audit: audit, WorkDir: c.work}
	if kind == "garmr" {
		o.Bin, o.PolicyDir = c.garmrBin, garmrDir
	} else {
		o.Bin, o.PolicyDir = c.opaBin, opaDir
	}
	return startServer(o)
}

func verify(c config, res *Results, sc *Scenario, kind string) {
	s, _, err := launch(c, sc, kind, false)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("%s/%s: start: %v", kind, sc.Name, err))
		return
	}
	defer s.Stop()
	client := newClient(1)
	for _, cs := range sc.Cases {
		resp, err := post(client, s.EvalURL, cs.Body)
		if err == nil {
			err = checkResponse(kind, resp, cs.Want)
		}
		// The checker must reject a wrong answer, or a pass means nothing.
		if err == nil && checkResponse(kind, resp, append(slices.Clone(cs.Want), "bogus")) == nil {
			err = fmt.Errorf("checker accepted a wrong expectation")
		}
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("%s/%s/%s: %v", kind, sc.Name, cs.Name, err))
			log.Printf("FAIL %s/%s/%s: %v", kind, sc.Name, cs.Name, err)
			continue
		}
		n := 2000
		if c.quick {
			n = 200
		}
		st := sequential(s, cs.Body, 200, n, 10*time.Second)
		res.Verify = append(res.Verify, VerifyResult{Server: kind, Scenario: sc.Name, Case: cs.Name, ReqBytes: len(cs.Body), Stats: st})
		log.Printf("ok   %-6s %-20s %-5s p50=%7.1fµs p99=%7.1fµs resp=%dB", kind, sc.Name, cs.Name, st.P50, st.P99, st.RespBytes)
	}
}

func startup(c config, res *Results, sc *Scenario, kind string) {
	var ms, rss []float64
	for i := 0; i < max(c.runs, 1); i++ {
		s, d, err := launch(c, sc, kind, false)
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("%s/%s: start: %v", kind, sc.Name, err))
			return
		}
		r, _ := memKB(s.Pid())
		s.Stop()
		ms = append(ms, float64(d.Microseconds())/1e3)
		rss = append(rss, float64(r)/1024)
	}
	r := StartupResult{Server: kind, Scenario: sc.Name, Policies: len(sc.Garmr), ReadyMs: median(ms), RSSMB: median(rss), AllMs: ms}
	res.Startup = append(res.Startup, r)
	log.Printf("%-6s %-20s ready=%8.1fms rss=%6.1fMB", kind, sc.Name, r.ReadyMs, r.RSSMB)
}

func closed(c config, res *Results, sc *Scenario, kind string, conns []int) {
	s, _, err := launch(c, sc, kind, false)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("%s/%s: start: %v", kind, sc.Name, err))
		return
	}
	defer s.Stop()
	for _, n := range conns {
		var runs []Stats
		for i := 0; i < c.runs; i++ {
			runs = append(runs, closedLoop(s, sc.Load.Body, n, c.warm, c.dur))
		}
		sort.Slice(runs, func(i, j int) bool { return runs[i].RPS < runs[j].RPS })
		var rps []float64
		for _, r := range runs {
			rps = append(rps, r.RPS)
		}
		st := runs[len(runs)/2]
		res.Closed = append(res.Closed, LoadResult{Server: kind, Scenario: sc.Name, Conns: n, Stats: st, RunsRPS: rps})
		log.Printf("%-6s %-20s c=%-3d rps=%8.0f p50=%8.1fµs p99=%8.1fµs cpu/req=%6.1fµs srv=%.2f cli=%.2f cores err=%d",
			kind, sc.Name, n, st.RPS, st.P50, st.P99, st.CPUPerReq, st.ServerCores, st.ClientCores, st.Errors+st.NonAllow)
	}
}

func open(c config, res *Results, sc *Scenario, kind string, rates []int) {
	s, _, err := launch(c, sc, kind, false)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("%s/%s: start: %v", kind, sc.Name, err))
		return
	}
	for _, rate := range rates {
		st, _ := openLoop(s, sc.Load.Body, rate, c.warm, c.dur, nil)
		res.Open = append(res.Open, LoadResult{Server: kind, Scenario: sc.Name, Rate: rate, Stats: st})
		log.Printf("%-6s %-20s rate=%-6d got=%8.0f p50=%8.1fµs p99=%9.1fµs p999=%9.1fµs cpu/req=%6.1fµs lag p50/p99=%.0f/%.0fµs sat=%v",
			kind, sc.Name, rate, st.RPS, st.P50, st.P99, st.P999, st.CPUPerReq, st.SendLagP50, st.SendLagP99, st.Saturated)
	}
	s.Stop()

	// The same offered rates with Garmr's audit log / OPA's decision log on.
	sa, _, err := launch(c, sc, kind, true)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("%s/%s+audit: start: %v", kind, sc.Name, err))
		return
	}
	defer sa.Stop()
	auditRates := []int{5000, 20000}
	if c.quick {
		auditRates = []int{5000}
	}
	for _, rate := range auditRates {
		st, _ := openLoop(sa, sc.Load.Body, rate, c.warm, c.dur, nil)
		res.Open = append(res.Open, LoadResult{Server: kind, Scenario: sc.Name + "+audit", Rate: rate, Stats: st})
		log.Printf("%-6s %-20s rate=%-6d got=%8.0f p50=%8.1fµs p99=%9.1fµs p999=%9.1fµs cpu/req=%6.1fµs sat=%v",
			kind, sc.Name+"+audit", rate, st.RPS, st.P50, st.P99, st.P999, st.CPUPerReq, st.Saturated)
	}
}

func soak(c config, res *Results, kind string, rate int, dur time.Duration) {
	sc := simpleScenario()
	s, _, err := launch(c, sc, kind, false)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("%s/soak: start: %v", kind, err))
		return
	}
	defer s.Stop()
	var rss []float64
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(dur / 12)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				r, _ := memKB(s.Pid())
				rss = append(rss, float64(r)/1024)
			}
		}
	}()
	st, samples := openLoop(s, sc.Load.Body, rate, c.warm, dur, nil)
	close(stop)
	r := SoakResult{Server: kind, Rate: rate, Overall: st, RSSMB: rss}
	step := dur / 6
	for from := c.warm; from < c.warm+dur; from += step {
		r.Windows = append(r.Windows, window(samples, from, from+step))
	}
	res.Soak = append(res.Soak, r)
	log.Printf("%-6s soak rate=%d p50=%.1fµs p99=%.1fµs rss=%v", kind, rate, st.P50, st.P99, rss)
}

// reload runs steady load on many-indexed-500 and, a few seconds in,
// rewrites the policy the input matches so the input now violates it, then
// asks the server to pick up the change.
func reload(c config, res *Results, kind string, rate int) {
	sc := manyScenario(500, true)
	s, _, err := launch(c, sc, kind, false)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("%s/reload: start: %v", kind, err))
		return
	}
	defer s.Stop()

	target := 250
	file := fmt.Sprintf("p%d", target)
	at := c.warm + c.dur/3
	var callStart, callEnd time.Duration
	var callErr error
	called := make(chan struct{})
	during := func(start time.Time) {
		defer close(called)
		time.Sleep(time.Until(start.Add(at)))
		// p250-r1 now demands env == "dev"; the load input says "prod".
		if kind == "garmr" {
			src := strings.Replace(sc.Garmr[file+".cue"], `equals: "prod"`, `equals: "dev"`, 1)
			callErr = os.WriteFile(filepath.Join(s.PolicyDir, file+".cue"), []byte(src), 0o644)
			file += ".cue"
		} else {
			src := strings.Replace(sc.Rego[file+".rego"], `!= "prod"`, `!= "dev"`, 1)
			callErr = os.WriteFile(filepath.Join(s.PolicyDir, file+".rego"), []byte(src), 0o644)
			file += ".rego"
		}
		if callErr != nil {
			return
		}
		callStart = time.Since(start)
		callErr = s.Reload(context.Background(), file)
		callEnd = time.Since(start)
	}
	_, samples := openLoop(s, sc.Load.Body, rate, c.warm, c.dur, during)
	<-called
	if callErr != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("%s/reload: %v", kind, callErr))
		return
	}

	r := ReloadResult{Server: kind, Rate: rate, CallMs: ms(callEnd - callStart), EffectMs: -1}
	first := time.Duration(-1)
	for _, sm := range samples {
		if sm.lat < 0 || !sm.ok {
			continue
		}
		done := sm.due + sm.lat
		if sm.deny && (first < 0 || done < first) {
			first = done
		}
		if !sm.deny && sm.due > callEnd {
			r.StaleAfter++
		}
	}
	if first >= 0 {
		r.EffectMs = ms(first - callStart)
	}
	r.Before = window(samples, c.warm, callStart)
	r.During = window(samples, callStart, callEnd+time.Second)
	r.After = window(samples, callEnd+time.Second, c.warm+c.dur)
	res.Reload = append(res.Reload, r)
	log.Printf("%-6s reload rate=%d call=%.1fms effect=%.1fms stale=%d p99 before/during/after=%.0f/%.0f/%.0fµs max during=%.0fµs errors=%d",
		kind, rate, r.CallMs, r.EffectMs, r.StaleAfter, r.Before.P99, r.During.P99, r.After.P99, r.During.Max, r.During.Errors)
}

func post(c *http.Client, url string, body []byte) ([]byte, error) {
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err == nil && resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s: %.300s", resp.Status, b)
	}
	return b, err
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1e3 }

func median(v []float64) float64 {
	s := slices.Clone(v)
	sort.Float64s(s)
	return s[len(s)/2]
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func hostInfo(c config) map[string]string {
	h := map[string]string{
		"go":          runtime.Version(),
		"server_cpus": c.serverCPUs,
		"gomaxprocs":  fmt.Sprint(c.procs),
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "model name") {
				h["cpu"] = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
				break
			}
		}
	}
	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"); err == nil {
		h["governor"] = strings.TrimSpace(string(b))
	}
	return h
}
