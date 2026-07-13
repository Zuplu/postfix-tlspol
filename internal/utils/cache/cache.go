/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package cache

import (
	"compress/gzip"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Cacheable interface {
	RemainingTTL(...time.Time) uint32
	Age(...time.Time) uint32
}

type Expirable struct {
	ExpiresAt time.Time
}

func (e *Expirable) Age(t ...time.Time) uint32 {
	var now time.Time
	if len(t) == 0 {
		now = time.Now()
	} else {
		now = t[0]
	}
	age := now.Sub(e.ExpiresAt).Seconds()
	if age < 0 {
		age = 0
	}
	return uint32(age)
}

func (e *Expirable) RemainingTTL(t ...time.Time) uint32 {
	var now time.Time
	if len(t) == 0 {
		now = time.Now()
	} else {
		now = t[0]
	}
	ttl := e.ExpiresAt.Sub(now).Seconds()
	if ttl < 0 {
		ttl = 0
	}
	return uint32(ttl)
}

type Cache[T Cacheable] struct {
	data                   map[string]T
	quit                   chan struct{}
	filePath               string
	wg                     sync.WaitGroup
	closeOnce              sync.Once
	persistMu              sync.Mutex
	savePeriod             time.Duration
	dirty                  bool
	generation             uint64
	persistedGeneration    uint64
	hasPersistedGeneration bool
	sync.RWMutex
}

type Entry[T Cacheable] struct {
	Value T
	Key   string
}

func New[T Cacheable](filePath string, savePeriod time.Duration) *Cache[T] {
	c := &Cache[T]{
		data:       make(map[string]T),
		filePath:   filePath,
		savePeriod: savePeriod,
		quit:       make(chan struct{}),
	}
	if err := c.load(); err != nil {
		slog.Error("cache: error loading persisted data", "error", err)
	}
	c.wg.Add(1)
	go c.periodicSave()
	return c
}

func (c *Cache[T]) Set(key string, value T) {
	c.Lock()
	defer c.Unlock()
	c.data[key] = value
	c.dirty = true
	c.generation++
}

func (c *Cache[T]) Update(haveLock bool, key string, fn func(T, bool) (T, bool)) {
	if !haveLock {
		c.Lock()
		defer c.Unlock()
	}
	val, ok := c.data[key]
	next, update := fn(val, ok)
	if !update {
		return
	}
	c.data[key] = next
	c.dirty = true
	c.generation++
}

func (c *Cache[T]) Get(key string) (T, bool) {
	c.RLock()
	defer c.RUnlock()
	val, ok := c.data[key]
	return val, ok
}

func (c *Cache[T]) Remove(haveLock bool, key string) {
	if !haveLock {
		c.Lock()
		defer c.Unlock()
	}
	if _, ok := c.data[key]; !ok {
		return
	}
	delete(c.data, key)
	c.dirty = true
	c.generation++
}

func (c *Cache[T]) Purge() error {
	c.Lock()
	c.data = make(map[string]T)
	c.dirty = true
	c.generation++
	c.Unlock()
	return c.Save(false)
}

func (c *Cache[T]) Items(haveLock bool) []Entry[T] {
	if !haveLock {
		c.RLock()
		defer c.RUnlock()
	}
	entries := make([]Entry[T], 0, len(c.data))
	for k, v := range c.data {
		entries = append(entries, Entry[T]{Key: k, Value: v})
	}
	return entries
}

func (c *Cache[T]) Len() int {
	c.RLock()
	defer c.RUnlock()
	return len(c.data)
}

func (c *Cache[T]) Close() {
	c.closeOnce.Do(func() {
		close(c.quit)
		c.wg.Wait()
		if err := c.Save(false); err != nil {
			slog.Error("cache: error during final save", "error", err)
		}
	})
}

func (c *Cache[T]) periodicSave() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.savePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.Save(false); err != nil {
				slog.Error("cache: error saving cache", "error", err)
			}
		case <-c.quit:
			return
		}
	}
}

func (c *Cache[T]) Save(haveLock bool) error {
	return c.save(haveLock, false)
}

func (c *Cache[T]) ForceSave(haveLock bool) error {
	return c.save(haveLock, true)
}

func (c *Cache[T]) save(haveLock bool, force bool) error {
	var (
		snapshot   map[string]T
		generation uint64
	)
	if haveLock {
		if !force && !c.dirty {
			return nil
		}
		snapshot, generation = c.snapshotLocked()
	} else {
		c.Lock()
		if !force && !c.dirty {
			c.Unlock()
			return nil
		}
		snapshot, generation = c.snapshotLocked()
		c.Unlock()
	}

	if err := c.persistSnapshot(snapshot, generation, force); err != nil {
		return err
	}

	if haveLock {
		if c.generation == generation {
			c.dirty = false
		}
		return nil
	}

	c.Lock()
	if c.generation == generation {
		c.dirty = false
	}
	c.Unlock()
	return nil
}

func (c *Cache[T]) persistSnapshot(data map[string]T, generation uint64, force bool) error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()

	if c.hasPersistedGeneration {
		if generation < c.persistedGeneration || generation == c.persistedGeneration && !force {
			return nil
		}
	}
	if err := c.writeSnapshot(data); err != nil {
		return err
	}
	c.persistedGeneration = generation
	c.hasPersistedGeneration = true
	return nil
}

func (c *Cache[T]) snapshotLocked() (map[string]T, uint64) {
	snapshot := make(map[string]T, len(c.data))
	for k, v := range c.data {
		snapshot[k] = v
	}
	return snapshot, c.generation
}

func (c *Cache[T]) writeSnapshot(data map[string]T) error {
	dir := filepath.Dir(c.filePath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(c.filePath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	g, err := gzip.NewWriterLevel(tmp, gzip.BestSpeed)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := gob.NewEncoder(g).Encode(data); err != nil {
		_ = g.Close()
		_ = tmp.Close()
		return err
	}
	if err := g.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, c.filePath); err != nil {
		return err
	}
	removeTmp = false
	return syncDirectory(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (c *Cache[T]) load() error {
	f, err := os.Open(c.filePath)
	if err != nil {
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
	dec := gob.NewDecoder(g)
	var stored map[string]T
	if err := dec.Decode(&stored); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("cache: invalid trailing gob data: %w", err)
	} else if err == nil {
		return errors.New("cache: multiple gob values in snapshot")
	}
	if _, err := io.Copy(io.Discard, g); err != nil {
		return fmt.Errorf("cache: invalid compressed snapshot: %w", err)
	}
	if stored == nil {
		stored = make(map[string]T)
	}
	c.Lock()
	c.data = stored
	c.dirty = false
	c.hasPersistedGeneration = true
	c.Unlock()
	return nil
}
