package engine

import (
	"container/list"
	"fmt"
	"regexp"
	"sync"
)

const (
	// maxRegexCacheEntries bounds the compiled-pattern cache. Patterns can
	// originate from caller-supplied input (a `compare` with op "matches" and
	// a right-hand `path:` reference), so an unbounded cache lets any API
	// client grow server memory without limit.
	maxRegexCacheEntries = 1024

	// maxRegexPatternLen rejects absurd patterns before regexp.Compile spends
	// time and memory on them.
	maxRegexPatternLen = 512
)

// regexCache is an LRU cache of compiled regular expressions.
//
// It replaces a sync.Map with no eviction. Correctness did not depend on
// unbounded growth — only throughput does, and the LRU keeps the hot set.
type regexCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]*list.Element
	order   *list.List // front = most recently used
}

// regexCacheEntry is what the LRU list holds. Keeping the key alongside the
// value lets eviction find the map entry from the list element.
type regexCacheEntry struct {
	pattern string
	re      *regexp.Regexp
}

func newRegexCache(max int) *regexCache {
	if max <= 0 {
		max = maxRegexCacheEntries
	}
	return &regexCache{
		max:     max,
		entries: make(map[string]*list.Element),
		order:   list.New(),
	}
}

// get returns the compiled form of pattern, compiling and caching on miss.
func (c *regexCache) get(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("pattern too long: %d bytes (limit %d)", len(pattern), maxRegexPatternLen)
	}

	c.mu.Lock()
	if el, ok := c.entries[pattern]; ok {
		c.order.MoveToFront(el)
		re := el.Value.(*regexCacheEntry).re
		c.mu.Unlock()
		return re, nil
	}
	c.mu.Unlock()

	// Compile outside the lock: a pathological pattern must not block every
	// other evaluation in the process.
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Another goroutine may have compiled the same pattern while we were
	// outside the lock; prefer the existing entry so callers share one value.
	if el, ok := c.entries[pattern]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*regexCacheEntry).re, nil
	}

	el := c.order.PushFront(&regexCacheEntry{pattern: pattern, re: re})
	c.entries[pattern] = el

	for c.order.Len() > c.max {
		oldest := c.order.Back()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*regexCacheEntry).pattern)
	}

	return re, nil
}

// len reports the number of cached patterns. Used by tests.
func (c *regexCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
