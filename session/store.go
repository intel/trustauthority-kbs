/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package session

import (
	"sync"
	"time"

	"intel/kbs/v1/model"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

type Session struct {
	ID               string
	Nonce            string
	RequestedTEE     model.Tee
	Attested         bool
	AttestationToken string // JWT token from verifier
	ExpiresAt        time.Time
}

type InMemoryStore struct {
	mu              sync.RWMutex
	sessions        map[string]*Session
	ttl             time.Duration
	cleanupInterval time.Duration
	now             func() time.Time
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

func NewInMemoryStore(ttl, cleanupInterval time.Duration) *InMemoryStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if cleanupInterval <= 0 {
		cleanupInterval = time.Minute
	}

	s := &InMemoryStore{
		sessions:        make(map[string]*Session),
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		now:             time.Now,
		stopCh:          make(chan struct{}),
	}

	s.wg.Add(1)
	go s.cleanupLoop()

	return s
}

func (s *InMemoryStore) Create(nonce string) *Session {
	return s.CreateWithTEE(nonce, "")
}

func (s *InMemoryStore) CreateWithTEE(nonce string, tee model.Tee) *Session {
	now := s.now()
	sess := &Session{
		ID:           uuid.NewString(),
		Nonce:        nonce,
		RequestedTEE: tee,
		Attested:     false,
		ExpiresAt:    now.Add(s.ttl),
	}

	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()

	return cloneSession(sess)
}

func (s *InMemoryStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}

	if s.isExpired(sess) {
		s.Delete(id)
		return nil, false
	}

	return cloneSession(sess), true
}

func (s *InMemoryStore) MarkAttested(id string, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return errors.New("session not found")
	}
	if s.now().After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return errors.New("session expired")
	}

	sess.Attested = true
	sess.AttestationToken = token
	return nil
}

// StoreAttestationData stores the attestation token, marking the session as attested.
func (s *InMemoryStore) StoreAttestationData(id string, teePubKey *model.JWK, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return errors.New("session not found")
	}
	if s.now().After(sess.ExpiresAt) {
		delete(s.sessions, id)
		return errors.New("session expired")
	}

	sess.Attested = true
	sess.AttestationToken = token
	return nil
}

func (s *InMemoryStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *InMemoryStore) Close() {
	close(s.stopCh)
	s.wg.Wait()
}

func (s *InMemoryStore) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.removeExpired()
		case <-s.stopCh:
			return
		}
	}
}

func (s *InMemoryStore) removeExpired() {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

func (s *InMemoryStore) isExpired(sess *Session) bool {
	return s.now().After(sess.ExpiresAt)
}

func cloneSession(s *Session) *Session {
	if s == nil {
		return nil
	}

	clone := *s
	return &clone
}
