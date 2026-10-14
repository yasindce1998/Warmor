// Package cache memoises policy decisions.
package cache

import (
	"container/list"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// DecisionCache is a fixed-capacity LRU cache of policy decisions with a
// per-entry TTL. Get, Put and eviction are O(1); Get refreshes recency.
//
// A cached decision is reused for every event with the same Key, so the key
// covers every event field a policy can observe (see Key). The only field it
// can omit is the PID, and only for event types whose policy has declared it
// does not read the PID (SetPIDRelevant); otherwise every new process would
// be a guaranteed miss.
type DecisionCache struct {
	mu      sync.Mutex
	items   map[Key]*list.Element
	lru     *list.List // front = most recently used; values are *entry
	maxSize int
	ttl     time.Duration
	now     func() time.Time

	// pidRelevant reports whether decisions for an event type may depend on
	// the PID. nil means always (the safe default).
	pidRelevant func(api.EventType) bool

	hits      uint64
	misses    uint64
	evictions uint64
}

type entry struct {
	key       Key
	result    api.ActionResult
	expiresAt time.Time
}

// CacheStats contains cache statistics.
type CacheStats struct {
	Size      int
	MaxSize   int
	TotalHits uint64
	Misses    uint64
	Evictions uint64
}

// Key identifies the policy inputs of an event. It contains every field the
// host exposes to a policy module through either ABI (binary event struct or
// JSON document, internal/wasm/policy.go) or the get_field_* host callbacks
// (internal/wasm/hostcallback.go), plus the presence of each sub-event, since
// the serializers fall back to different values when one is nil. If a field
// is added to any of those, it must be added here too;
// TestKey_CoversEveryPolicyInput enforces this.
type Key struct {
	typ      api.EventType
	pid      uint32 // zero when the policy does not read it
	uid      uint32
	gid      uint32
	comm     string
	filename string

	hasProcess  bool
	procFile    string
	procArgs    string // length-prefixed join of Process.Args
	hasFile     bool
	fileOp      string
	filePath    string
	fileFlags   uint32
	hasNetwork  bool
	netOp       string
	netProto    string
	netRemote   string
	netRemotePt uint16
	netLocalPt  uint16
}

// NewDecisionCache creates a cache holding at most maxSize decisions, each
// valid for ttl. A non-positive maxSize disables caching.
func NewDecisionCache(maxSize int, ttl time.Duration) *DecisionCache {
	return &DecisionCache{
		items:   make(map[Key]*list.Element),
		lru:     list.New(),
		maxSize: maxSize,
		ttl:     ttl,
		now:     time.Now,
	}
}

// SetPIDRelevant installs the policy's PID dependency (typically derived
// from its fields-read declaration) and clears the cache, since existing
// keys were built under the previous rule. A nil f means every event type
// depends on the PID.
func (c *DecisionCache) SetPIDRelevant(f func(api.EventType) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pidRelevant = f
	c.clearLocked()
}

// Get retrieves a cached decision. The returned result is a copy with
// Cached set.
func (c *DecisionCache) Get(event *api.Event) (*api.ActionResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.makeKey(event)
	el, ok := c.items[key]
	if !ok {
		c.misses++
		return nil, false
	}
	e := entryOf(el)
	if !c.now().Before(e.expiresAt) {
		c.removeLocked(el)
		c.misses++
		return nil, false
	}
	c.lru.MoveToFront(el)
	c.hits++
	result := e.result
	result.Cached = true
	return &result, true
}

// Put stores a decision, evicting the least recently used entry if full.
func (c *DecisionCache) Put(event *api.Event, result *api.ActionResult) {
	if result == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxSize <= 0 {
		return
	}

	key := c.makeKey(event)
	expires := c.now().Add(c.ttl)
	if el, ok := c.items[key]; ok {
		e := entryOf(el)
		e.result = *result
		e.expiresAt = expires
		c.lru.MoveToFront(el)
		return
	}
	for c.lru.Len() >= c.maxSize {
		c.removeLocked(c.lru.Back())
		c.evictions++
	}
	c.items[key] = c.lru.PushFront(&entry{key: key, result: *result, expiresAt: expires})
}

// Clear removes all entries.
func (c *DecisionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
}

func (c *DecisionCache) clearLocked() {
	c.items = make(map[Key]*list.Element)
	c.lru.Init()
}

// entryOf returns the cache entry held by an LRU list element. The list only
// ever holds *entry values.
func entryOf(el *list.Element) *entry {
	e, _ := el.Value.(*entry)
	return e
}

func (c *DecisionCache) removeLocked(el *list.Element) {
	delete(c.items, entryOf(el).key)
	c.lru.Remove(el)
}

// Stats returns cache statistics. Hit, miss and eviction counts are totals
// since creation.
func (c *DecisionCache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CacheStats{
		Size:      c.lru.Len(),
		MaxSize:   c.maxSize,
		TotalHits: c.hits,
		Misses:    c.misses,
		Evictions: c.evictions,
	}
}

func (c *DecisionCache) makeKey(event *api.Event) Key {
	typ := event.GetType()
	k := Key{
		typ:      typ,
		uid:      event.UID,
		gid:      event.GID,
		comm:     event.Comm,
		filename: event.Filename,
	}
	if c.pidRelevant == nil || c.pidRelevant(typ) {
		k.pid = event.PID
	}
	if p := event.Process; p != nil {
		k.hasProcess = true
		k.procFile = p.Filename
		if len(p.Args) > 0 {
			k.procArgs = joinArgs(p.Args)
		}
	}
	if f := event.File; f != nil {
		k.hasFile = true
		k.fileOp = f.Operation
		k.filePath = f.Path
		k.fileFlags = f.Flags
	}
	if n := event.Network; n != nil {
		k.hasNetwork = true
		k.netOp = n.Operation
		k.netProto = n.Protocol
		k.netRemote = n.RemoteAddr
		k.netRemotePt = n.RemotePort
		k.netLocalPt = n.LocalPort
	}
	return k
}

// joinArgs encodes args unambiguously (length-prefixed), so different
// argument vectors never produce the same key.
func joinArgs(args []string) string {
	var b strings.Builder
	for _, a := range args {
		b.WriteString(strconv.Itoa(len(a)))
		b.WriteByte(':')
		b.WriteString(a)
	}
	return b.String()
}
