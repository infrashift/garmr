package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Stats summarises one measured window. Latencies are in microseconds.
type Stats struct {
	Requests int64   `json:"requests"`
	Errors   int64   `json:"errors"`
	NonAllow int64   `json:"non_allow"` // 200 responses without the allow marker
	Dropped  int64   `json:"dropped,omitempty"`
	Offered  float64 `json:"offered_rps,omitempty"`
	RPS      float64 `json:"rps"`
	Mean     float64 `json:"mean_us"`
	P50      float64 `json:"p50_us"`
	P90      float64 `json:"p90_us"`
	P99      float64 `json:"p99_us"`
	P999     float64 `json:"p999_us"`
	Max      float64 `json:"max_us"`
	// Server resources over the window.
	CPUPerReq   float64 `json:"server_cpu_us_per_req"`
	ServerCores float64 `json:"server_cores"`
	ClientCores float64 `json:"client_cores"`
	PeakRSSMB   float64 `json:"peak_rss_mb"`
	// Open loop only: how late the load generator sent requests. Large
	// values mean the generator, not the server, limited the run.
	SendLagP50   float64 `json:"send_lag_p50_us,omitempty"`
	SendLagP99   float64 `json:"send_lag_p99_us,omitempty"`
	RespBytes    int     `json:"resp_bytes"`
	Saturated    bool    `json:"saturated,omitempty"`
	DurationSecs float64 `json:"duration_s"`
}

// sample is one request in an open-loop run, kept for timelines.
type sample struct {
	due  time.Duration // intended send time, from run start
	lat  time.Duration // completion - due
	lag  time.Duration // actual send - due: load generator scheduling delay
	ok   bool
	deny bool
}

func newClient(conns int) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        conns,
			MaxIdleConnsPerHost: conns,
			MaxConnsPerHost:     conns,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
		},
	}
}

// do sends one evaluation and reports (transport/status ok, allow marker seen).
func do(ctx context.Context, c *http.Client, url string, payload []byte, marker []byte, buf *bytes.Buffer) (ok, allow bool, n int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false, false, 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return false, false, 0
	}
	buf.Reset()
	_, err = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return false, false, buf.Len()
	}
	return true, bytes.Contains(buf.Bytes(), marker), buf.Len()
}

func markerFor(kind string) []byte {
	if kind == "garmr" {
		return []byte(garmrAllowMarker)
	}
	return []byte(opaAllowMarker)
}

// resourceWatch samples server CPU and RSS across a measured window.
type resourceWatch struct {
	pid                  int
	cpu0, selfCPU0       time.Duration
	t0                   time.Time
	peak                 atomic.Int64
	stop                 chan struct{}
	done                 chan struct{}
	serverCPU, clientCPU time.Duration
	wall                 time.Duration
}

func watch(pid int) *resourceWatch {
	w := &resourceWatch{pid: pid, stop: make(chan struct{}), done: make(chan struct{})}
	w.cpu0, _ = cpuTime(pid)
	w.selfCPU0, _ = cpuTime(os.Getpid())
	w.t0 = time.Now()
	go func() {
		defer close(w.done)
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			rss, _ := memKB(pid)
			if rss > w.peak.Load() {
				w.peak.Store(rss)
			}
			select {
			case <-w.stop:
				return
			case <-t.C:
			}
		}
	}()
	return w
}

// watchFrom starts a resourceWatch at time at.
func watchFrom(pid int, at time.Time) <-chan *resourceWatch {
	ch := make(chan *resourceWatch, 1)
	go func() {
		time.Sleep(time.Until(at))
		ch <- watch(pid)
	}()
	return ch
}

func (w *resourceWatch) end() {
	close(w.stop)
	<-w.done
	c1, _ := cpuTime(w.pid)
	s1, _ := cpuTime(os.Getpid())
	w.wall = time.Since(w.t0)
	w.serverCPU, w.clientCPU = c1-w.cpu0, s1-w.selfCPU0
}

func (w *resourceWatch) fill(st *Stats) {
	secs := w.wall.Seconds()
	st.ServerCores = w.serverCPU.Seconds() / secs
	st.ClientCores = w.clientCPU.Seconds() / secs
	if st.Requests > 0 {
		st.CPUPerReq = float64(w.serverCPU.Microseconds()) / float64(st.Requests)
	}
	st.PeakRSSMB = float64(w.peak.Load()) / 1024
}

func summarise(lat []time.Duration, st *Stats) {
	if len(lat) == 0 {
		return
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	var sum time.Duration
	for _, d := range lat {
		sum += d
	}
	us := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e3 }
	pct := func(p float64) float64 { return us(lat[min(len(lat)-1, int(p*float64(len(lat))))]) }
	st.Mean = us(sum / time.Duration(len(lat)))
	st.P50, st.P90, st.P99, st.P999 = pct(0.50), pct(0.90), pct(0.99), pct(0.999)
	st.Max = us(lat[len(lat)-1])
}

// sequential sends n requests one at a time on one connection.
func sequential(s *Server, payload []byte, warm, n int, budget time.Duration) Stats {
	c := newClient(1)
	marker := markerFor(s.Kind)
	var buf bytes.Buffer
	var st Stats
	for i := 0; i < warm; i++ {
		do(context.Background(), c, s.EvalURL, payload, marker, &buf)
	}
	lat := make([]time.Duration, 0, n)
	start := time.Now()
	for i := 0; i < n && time.Since(start) < budget; i++ {
		t := time.Now()
		ok, allow, nb := do(context.Background(), c, s.EvalURL, payload, marker, &buf)
		lat = append(lat, time.Since(t))
		st.Requests++
		st.RespBytes = nb
		if !ok {
			st.Errors++
		} else if !allow {
			st.NonAllow++
		}
	}
	st.DurationSecs = time.Since(start).Seconds()
	st.RPS = float64(st.Requests) / st.DurationSecs
	summarise(lat, &st)
	return st
}

// closedLoop runs conns workers back to back for warm+dur and measures
// requests that complete inside the final dur (server CPU is sampled over
// the same window, so CPU/req stays honest for slow requests).
func closedLoop(s *Server, payload []byte, conns int, warm, dur time.Duration) Stats {
	c := newClient(conns)
	marker := markerFor(s.Kind)
	start := time.Now()
	t1, t2 := start.Add(warm), start.Add(warm+dur)

	wch := watchFrom(s.Pid(), start.Add(warm))

	var (
		mu       sync.Mutex
		all      []time.Duration
		st       Stats
		wg       sync.WaitGroup
		respSize atomic.Int64
	)
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			lat := make([]time.Duration, 0, 1<<16)
			var reqs, errs, nonAllow int64
			for {
				t := time.Now()
				if !t.Before(t2) {
					break
				}
				ok, allow, nb := do(context.Background(), c, s.EvalURL, payload, marker, &buf)
				e := time.Now()
				if e.Before(t1) || e.After(t2) {
					continue
				}
				reqs++
				lat = append(lat, e.Sub(t))
				respSize.Store(int64(nb))
				if !ok {
					errs++
				} else if !allow {
					nonAllow++
				}
			}
			mu.Lock()
			all = append(all, lat...)
			st.Requests += reqs
			st.Errors += errs
			st.NonAllow += nonAllow
			mu.Unlock()
		}()
	}
	wg.Wait()
	w := <-wch
	w.end()
	st.DurationSecs = dur.Seconds()
	st.RPS = float64(st.Requests) / dur.Seconds()
	st.RespBytes = int(respSize.Load())
	summarise(all, &st)
	w.fill(&st)
	c.CloseIdleConnections()
	return st
}

// openLoop offers a fixed request rate for warm+dur regardless of how fast
// the server answers. Latency is measured from each request's intended send
// time, so queueing delay counts (no coordinated omission). Requests still
// queued 2s after the window are dropped and the run is marked saturated.
// The returned samples cover the whole run, warmup included.
func openLoop(s *Server, payload []byte, rate int, warm, dur time.Duration, during func(start time.Time)) (Stats, []sample) {
	const workers = 256
	c := newClient(workers)
	marker := markerFor(s.Kind)
	total := int(float64(rate) * (warm + dur).Seconds())
	jobs := make(chan int, total)
	samples := make([]sample, total)
	interval := time.Second / time.Duration(rate)

	start := time.Now()
	drainBy := start.Add(warm + dur + 2*time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), drainBy)
	defer cancel()

	wch := watchFrom(s.Pid(), start.Add(warm))
	if during != nil {
		go during(start)
	}

	var wg sync.WaitGroup
	var dropped atomic.Int64
	var respSize atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf bytes.Buffer
			for j := range jobs {
				due := time.Duration(j) * interval
				if time.Now().After(drainBy) {
					dropped.Add(1)
					samples[j] = sample{due: due, lat: -1}
					continue
				}
				lag := time.Since(start.Add(due))
				ok, allow, nb := do(ctx, c, s.EvalURL, payload, marker, &buf)
				samples[j] = sample{due: due, lat: time.Since(start.Add(due)), lag: lag, ok: ok, deny: ok && !allow}
				if ok {
					respSize.Store(int64(nb))
				}
			}
		}()
	}

	// Dispatch every request that is due. Sleep only while the next one is
	// well in the future and spin for the last stretch: timer wakeups on an
	// idle core can be late by far more than a request takes.
	for sent := 0; sent < total; {
		elapsed := time.Since(start)
		due := min(total, int(elapsed/interval)+1)
		for ; sent < due; sent++ {
			jobs <- sent
		}
		if wait := time.Duration(sent)*interval - elapsed; wait > 2*time.Millisecond {
			time.Sleep(wait - 1500*time.Microsecond)
		} else {
			runtime.Gosched()
		}
	}
	close(jobs)
	wg.Wait()
	w := <-wch
	w.end()

	st := Stats{Offered: float64(rate), DurationSecs: dur.Seconds(), Dropped: dropped.Load(), RespBytes: int(respSize.Load())}
	var lat, lags []time.Duration
	var completedInWindow int64
	for _, sm := range samples {
		if sm.due < warm || sm.lat < 0 {
			continue
		}
		st.Requests++
		lat = append(lat, sm.lat)
		lags = append(lags, sm.lag)
		if !sm.ok {
			st.Errors++
			continue
		}
		if sm.deny {
			st.NonAllow++
		}
		if sm.due+sm.lat <= warm+dur {
			completedInWindow++
		}
	}
	st.RPS = float64(completedInWindow) / dur.Seconds()
	var lagStats Stats
	summarise(lags, &lagStats)
	st.SendLagP50, st.SendLagP99 = lagStats.P50, lagStats.P99
	summarise(lat, &st)
	w.fill(&st)
	st.Saturated = st.Dropped > 0 || st.Errors > 0 || st.RPS < 0.97*float64(rate)
	c.CloseIdleConnections()
	return st, samples
}

// window summarises the samples whose intended send time falls in [from, to).
func window(samples []sample, from, to time.Duration) Stats {
	var st Stats
	var lat []time.Duration
	for _, sm := range samples {
		if sm.due < from || sm.due >= to || sm.lat < 0 {
			continue
		}
		st.Requests++
		lat = append(lat, sm.lat)
		if !sm.ok {
			st.Errors++
		} else if sm.deny {
			st.NonAllow++
		}
	}
	st.DurationSecs = (to - from).Seconds()
	st.RPS = float64(st.Requests) / st.DurationSecs
	summarise(lat, &st)
	return st
}
