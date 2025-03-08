package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"os"
	"sync"
	"time"
)

type Cacheable interface {
	RemainingTTL() uint32
}

type Expirable struct {
	ExpiresAt time.Time
}

func (e *Expirable) RemainingTTL() uint32 {
	ttl := time.Until(e.ExpiresAt).Seconds()
	if ttl < 0 {
		ttl = 0
	}
	return uint32(ttl)
}

// Cache provides a thread-safe cache with persistence.
type Cache[T Cacheable] struct {
	mu         sync.RWMutex
	data       map[string]T
	filePath   string
	savePeriod time.Duration
	quit       chan struct{}
	wg         sync.WaitGroup
}

// Entry represents a key/value pair stored in the cache.
type Entry[T Cacheable] struct {
	Key   string
	Value T
}

// New returns a new Cache instance.
// filePath: The path to the gob file used for persistence.
// savePeriod: Duration between periodic auto-saves.
func New[T Cacheable](_ T, filePath string, savePeriod time.Duration) *Cache[T] {
	c := &Cache[T]{
		data:       make(map[string]T),
		filePath:   filePath,
		savePeriod: savePeriod,
		quit:       make(chan struct{}),
	}

	// Attempt to load persisted data on start.
	if err := c.load(); err != nil {
		log.Errorf("cache: error loading persisted data: %v", err)
	}

	// Start background worker for periodic saving.
	c.wg.Add(1)
	go c.periodicSave()
	return c
}

// Set stores the given value with the specified key.
// If the key already exists, it overwrites the previous value.
func (c *Cache[T]) Set(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
}

// Get retrieves the value for the specified key.
// The second return value indicates whether the key was found.
func (c *Cache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.data[key]
	return val, ok
}

// Remove deletes the key-value pair for the specified key.
func (c *Cache[T]) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}

// Purge removes all entries from the cache.
func (c *Cache[T]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]T)
	c.save()
}

// Items returns a slice of all the cache entries as key/value pairs.
// This allows you to safely iterate over a snapshot of the cache.
func (c *Cache[T]) Items() []Entry[T] {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entries := make([]Entry[T], 0, len(c.data))
	for k, v := range c.data {
		entries = append(entries, Entry[T]{Key: k, Value: v})
	}
	return entries
}

// Close stops the periodic saving goroutine and performs a final save.
func (c *Cache[T]) Close() {
	close(c.quit)
	c.wg.Wait()
	// Final save before exit.
	if err := c.save(); err != nil {
		log.Errorf("cache: error during final save: %v", err)
	}
}

// periodicSave runs a loop that saves the cache periodically until closed.
func (c *Cache[T]) periodicSave() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.savePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.save(); err != nil {
				log.Errorf("cache: error saving cache: %v", err)
			}
		case <-c.quit:
			return
		}
	}
}

// save persists the current state of the cache to the gob file.
// It serializes the internal map into a byte buffer before writing the file.
func (c *Cache[T]) save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Encode the map to a buffer.
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(c.data); err != nil {
		return err
	}

	// Write to file.
	f, err := os.Create(c.filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	g, err := gzip.NewWriterLevel(f, gzip.BestSpeed)
	if err != nil {
		return err
	}
	defer g.Close()
	if _, err := g.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

// load restores the cache state from the gob file.
// If the file does not exist, load simply returns without error.
func (c *Cache[T]) load() error {
	f, err := os.Open(c.filePath)
	if err != nil {
		// If file doesn't exist, nothing to load.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	g, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer g.Close()

	// Decode the file into a map.
	dec := gob.NewDecoder(g)
	var stored map[string]T
	if err := dec.Decode(&stored); err != nil {
		return err
	}

	c.mu.Lock()
	c.data = stored
	c.mu.Unlock()
	return nil
}
