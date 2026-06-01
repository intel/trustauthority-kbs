/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package session

import (
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"
)

func TestInMemoryStoreCreateAndGet(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(time.Minute, time.Minute)
	defer store.Close()

	created := store.Create("nonce-1")
	fetched, ok := store.Get(created.ID)

	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(fetched.ID).To(gomega.Equal(created.ID))
	g.Expect(fetched.Nonce).To(gomega.Equal("nonce-1"))
	g.Expect(fetched.Attested).To(gomega.BeFalse())
}

func TestInMemoryStoreGetExpiredRemovesSession(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(20*time.Millisecond, 10*time.Millisecond)
	defer store.Close()

	created := store.Create("nonce-2")
	time.Sleep(40 * time.Millisecond)

	_, ok := store.Get(created.ID)
	g.Expect(ok).To(gomega.BeFalse())
}

func TestInMemoryStoreMarkAttested(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(time.Minute, time.Minute)
	defer store.Close()

	created := store.Create("nonce-3")
	err := store.MarkAttested(created.ID, "test-token")
	g.Expect(err).NotTo(gomega.HaveOccurred())

	fetched, ok := store.Get(created.ID)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(fetched.Attested).To(gomega.BeTrue())
	g.Expect(fetched.AttestationToken).To(gomega.Equal("test-token"))
}

func TestInMemoryStoreConcurrentAccess(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(time.Minute, time.Minute)
	defer store.Close()

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	ids := make(chan string, workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			s := store.Create("nonce")
			ids <- s.ID
		}()
	}

	wg.Wait()
	close(ids)

	for id := range ids {
		_, ok := store.Get(id)
		g.Expect(ok).To(gomega.BeTrue())
	}
}
