/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

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

type Cache[T Cacheable] struct {
	mu         sync.RWMutex
	data       map[string]T
	filePath   string
	savePeriod time.Duration
	quit       chan struct{}
	wg         sync.WaitGroup
	dirty      bool
}

type Entry[T Cacheable] struct {
	Key   string
	Value T
}

func New[T Cacheable](_ T, filePath string, savePeriod time.Duration) *Cache[T] {
	c := &Cache[T]{
		data:       make(map[string]T),
		filePath:   filePath,
		savePeriod: savePeriod,
		quit:       make(chan struct{}),
	}

	if err := c.load(); err != nil {
		log.Errorf("cache: error loading persisted data: %v", err)
	}

	c.wg.Add(1)
	go c.periodicSave()
	return c
}

func (c *Cache[T]) Set(key string, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = value
	c.dirty = true
}

func (c *Cache[T]) Get(key string) (T, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.data[key]
	return val, ok
}

func (c *Cache[T]) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
	c.dirty = true
}

func (c *Cache[T]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]T)
	c.dirty = true
}

func (c *Cache[T]) Items() []Entry[T] {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entries := make([]Entry[T], 0, len(c.data))
	for k, v := range c.data {
		entries = append(entries, Entry[T]{Key: k, Value: v})
	}
	return entries
}

func (c *Cache[T]) Close() {
	close(c.quit)
	c.wg.Wait()
	if err := c.save(); err != nil {
		log.Errorf("cache: error during final save: %v", err)
	}
}

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

func (c *Cache[T]) save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.dirty {
		return nil
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(c.data); err != nil {
		return err
	}

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
	c.dirty = false
	return nil
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

	c.mu.Lock()
	c.data = stored
	c.dirty = false
	c.mu.Unlock()
	return nil
}
