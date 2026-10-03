package main

import (
	"fmt"
	"strings"
)

// render prints the results as side-by-side markdown tables.
func render(r *Results) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("# Garmr vs OPA, end to end\n\n")
	w("%s · governor %s · servers on CPUs %s, GOMAXPROCS=%s · %s\n\n",
		r.Host["cpu"], r.Host["governor"], r.Host["server_cpus"], r.Host["gomaxprocs"], r.Started.Format("2006-01-02 15:04"))
	if len(r.Failures) > 0 {
		w("## FAILURES\n\n")
		for _, f := range r.Failures {
			w("- %s\n", f)
		}
		w("\n")
	}

	if len(r.Verify) > 0 {
		w("## Verified, sequential latency (1 connection)\n\n")
		w("| Scenario | Case | Req | Garmr p50 | Garmr p99 | Garmr resp | OPA p50 | OPA p99 | OPA resp | OPA/Garmr p50 |\n|---|---|--:|--:|--:|--:|--:|--:|--:|--:|\n")
		idx := map[string]VerifyResult{}
		var keys []string
		for _, v := range r.Verify {
			k := v.Scenario + "/" + v.Case
			if _, ok := idx["garmr/"+k]; !ok {
				if _, ok := idx["opa/"+k]; !ok {
					keys = append(keys, k)
				}
			}
			idx[v.Server+"/"+k] = v
		}
		for _, k := range keys {
			g, o := idx["garmr/"+k], idx["opa/"+k]
			sc, cs, _ := strings.Cut(k, "/")
			req := g.ReqBytes
			if req == 0 {
				req = o.ReqBytes
			}
			w("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", sc, cs, bytesStr(req),
				us(g.Stats.P50), us(g.Stats.P99), bytesStr(g.Stats.RespBytes),
				us(o.Stats.P50), us(o.Stats.P99), bytesStr(o.Stats.RespBytes), ratio(o.Stats.P50, g.Stats.P50))
		}
		w("\n")
	}

	if len(r.Startup) > 0 {
		w("## Startup (exec → ready) and RSS\n\n")
		w("| Scenario | Policies | Garmr ready | Garmr RSS | OPA ready | OPA RSS |\n|---|--:|--:|--:|--:|--:|\n")
		idx := map[string]StartupResult{}
		var keys []string
		for _, s := range r.Startup {
			if _, ok := idx["x/"+s.Scenario]; !ok {
				keys = append(keys, s.Scenario)
				idx["x/"+s.Scenario] = s
			}
			idx[s.Server+"/"+s.Scenario] = s
		}
		for _, k := range keys {
			g, o := idx["garmr/"+k], idx["opa/"+k]
			w("| %s | %d | %s | %s | %s | %s |\n", k, idx["x/"+k].Policies,
				msStr(g.ReadyMs), mb(g.RSSMB), msStr(o.ReadyMs), mb(o.RSSMB))
		}
		w("\n")
	}

	if len(r.Closed) > 0 {
		w("## Closed loop: throughput by concurrency (median of runs)\n\n")
		w("| Scenario | Conns | Garmr req/s | p50 | p99 | CPU/req | OPA req/s | p50 | p99 | CPU/req | Garmr/OPA req/s | client cores (G/O) |\n|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|\n")
		idx := map[string]LoadResult{}
		var keys []string
		for _, l := range r.Closed {
			k := fmt.Sprintf("%s/%d", l.Scenario, l.Conns)
			if _, ok := idx["x/"+k]; !ok {
				keys = append(keys, k)
				idx["x/"+k] = l
			}
			idx[l.Server+"/"+k] = l
		}
		for _, k := range keys {
			g, o, x := idx["garmr/"+k], idx["opa/"+k], idx["x/"+k]
			w("| %s | %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %.1f / %.1f |\n", x.Scenario, x.Conns,
				num(g.Stats.RPS), us(g.Stats.P50), us(g.Stats.P99), us(g.Stats.CPUPerReq),
				num(o.Stats.RPS), us(o.Stats.P50), us(o.Stats.P99), us(o.Stats.CPUPerReq),
				ratio(g.Stats.RPS, o.Stats.RPS), g.Stats.ClientCores, o.Stats.ClientCores)
		}
		w("\n")
	}

	if len(r.Open) > 0 {
		w("## Open loop: latency at a fixed offered rate\n\nLatency is measured from each request's scheduled send time. *sat* = the server could not keep up (dropped/errored or <97%% of offered).\n\n")
		w("| Server | Scenario | Offered | Achieved | p50 | p90 | p99 | p99.9 | max | CPU/req | server cores | gen lag p99 | |\n|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|\n")
		for _, l := range r.Open {
			sat := ""
			if l.Stats.Saturated {
				sat = "sat"
			}
			w("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %.2f | %s | %s |\n", l.Server, l.Scenario, num(float64(l.Rate)), num(l.Stats.RPS),
				us(l.Stats.P50), us(l.Stats.P90), us(l.Stats.P99), us(l.Stats.P999), us(l.Stats.Max), us(l.Stats.CPUPerReq), l.Stats.ServerCores, us(l.Stats.SendLagP99), sat)
		}
		w("\n")
	}

	if len(r.Soak) > 0 {
		w("## Soak\n\n| Server | Rate | p50 | p99 | p99 per window | RSS samples (MB) |\n|---|--:|--:|--:|---|---|\n")
		for _, s := range r.Soak {
			var p99s, rss []string
			for _, win := range s.Windows {
				p99s = append(p99s, us(win.P99))
			}
			for _, v := range s.RSSMB {
				rss = append(rss, fmt.Sprintf("%.0f", v))
			}
			w("| %s | %s | %s | %s | %s | %s |\n", s.Server, num(float64(s.Rate)), us(s.Overall.P50), us(s.Overall.P99),
				strings.Join(p99s, " "), strings.Join(rss, " "))
		}
		w("\n")
	}

	if len(r.Reload) > 0 {
		w("## Policy reload under load (500 indexed policies, one rewritten)\n\n")
		w("| Server | Rate | Reload call | New policy seen after | Stale after return | p99 before | p99 during | max during | p99 after | errors |\n|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|\n")
		for _, l := range r.Reload {
			w("| %s | %s | %s | %s | %d | %s | %s | %s | %s | %d |\n", l.Server, num(float64(l.Rate)), msStr(l.CallMs), msStr(l.EffectMs), l.StaleAfter,
				us(l.Before.P99), us(l.During.P99), us(l.During.Max), us(l.After.P99), l.Before.Errors+l.During.Errors+l.After.Errors)
		}
		w("\n")
	}
	return b.String()
}

func us(v float64) string {
	switch {
	case v == 0:
		return "–"
	case v >= 10000:
		return fmt.Sprintf("%.1f ms", v/1000)
	case v >= 1000:
		return fmt.Sprintf("%.2f ms", v/1000)
	default:
		return fmt.Sprintf("%.0f µs", v)
	}
}

func msStr(v float64) string {
	if v <= 0 {
		return "–"
	}
	if v >= 1000 {
		return fmt.Sprintf("%.2f s", v/1000)
	}
	return fmt.Sprintf("%.0f ms", v)
}

func mb(v float64) string {
	if v == 0 {
		return "–"
	}
	return fmt.Sprintf("%.0f MB", v)
}

func num(v float64) string {
	if v == 0 {
		return "–"
	}
	if v >= 1000 {
		return fmt.Sprintf("%.1fk", v/1000)
	}
	return fmt.Sprintf("%.0f", v)
}

func bytesStr(n int) string {
	switch {
	case n == 0:
		return "–"
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func ratio(a, b float64) string {
	if a == 0 || b == 0 {
		return "–"
	}
	return fmt.Sprintf("%.1f×", a/b)
}
