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

	"intel/kbs/v1/model"

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

func TestInMemoryStoreDefaultTTLAndCleanup(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(0, 0)
	defer store.Close()

	g.Expect(store.ttl).To(gomega.Equal(5 * time.Minute))
	g.Expect(store.cleanupInterval).To(gomega.Equal(time.Minute))
}

func TestInMemoryStoreCreateWithTEEAndGetMissingSession(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(time.Minute, time.Minute)
	defer store.Close()

	sess := store.CreateWithTEE("nonce-tee", "sgx")
	g.Expect(sess.RequestedTEE).To(gomega.Equal(model.Tee("sgx")))

	_, ok := store.Get("missing-id")
	g.Expect(ok).To(gomega.BeFalse())
}

func TestInMemoryStoreMarkAttestedAndStoreAttestationData(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(time.Minute, time.Minute)
	defer store.Close()

	sess := store.Create("nonce-4")

	err := store.MarkAttested(sess.ID, "token-1")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(store.sessions[sess.ID].AttestationToken).To(gomega.Equal("token-1"))

	err = store.StoreAttestationData(sess.ID, "token-2")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(store.sessions[sess.ID].AttestationToken).To(gomega.Equal("token-2"))
}

func TestInMemoryStoreExpiredAndNotFoundBranches(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	store := NewInMemoryStore(20*time.Millisecond, 10*time.Millisecond)
	defer store.Close()

	sess := store.Create("nonce-exp")
	store.Delete(sess.ID)
	g.Expect(store.sessions).NotTo(gomega.HaveKey(sess.ID))

	err := store.MarkAttested("missing", "token")
	g.Expect(err).To(gomega.HaveOccurred())

	err = store.StoreAttestationData("missing", "token")
	g.Expect(err).To(gomega.HaveOccurred())

	newSession := store.Create("nonce-exp-2")
	store.sessions[newSession.ID].ExpiresAt = time.Now().Add(-time.Second)
	_, ok := store.Get(newSession.ID)
	g.Expect(ok).To(gomega.BeFalse())

	store.removeExpired()
	g.Expect(store.sessions).NotTo(gomega.HaveKey(newSession.ID))
}

func TestCloneSessionNil(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	g.Expect(cloneSession(nil)).To(gomega.BeNil())
}
