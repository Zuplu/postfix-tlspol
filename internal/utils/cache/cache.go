/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package cache

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"os"
	"sync"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
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
	data       map[string]T
	quit       chan struct{}
	filePath   string
	wg         sync.WaitGroup
	savePeriod time.Duration
	dirty      bool
	sync.RWMutex
}

type Entry[T Cacheable] struct {
	Value T
	Key   string
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
	c.Lock()
	defer c.Unlock()
	c.data[key] = value
	c.dirty = true
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
	delete(c.data, key)
	c.dirty = true
}

func (c *Cache[T]) Purge() {
	c.Lock()
	defer c.Unlock()
	c.data = make(map[string]T)
	c.dirty = true
	c.Save(true)
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

func (c *Cache[T]) Close() {
	close(c.quit)
	c.wg.Wait()
	if err := c.Save(false); err != nil {
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
			go func() {
				if err := c.Save(false); err != nil {
					log.Errorf("cache: error saving cache: %v", err)
				}
			}()
		case <-c.quit:
			return
		}
	}
}

func (c *Cache[T]) Save(haveLock bool) error {
	if !haveLock {
		c.RLock()
	}
	if !c.dirty {
		if !haveLock {
			c.RUnlock()
		}
		return nil
	}
	if !haveLock {
		c.RUnlock()
		c.Lock()
		defer c.Unlock()
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
	c.Lock()
	c.data = stored
	c.dirty = false
	c.Unlock()
	return nil
}
