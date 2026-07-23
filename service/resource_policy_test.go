/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"intel/kbs/v1/model"

	"github.com/onsi/gomega"
)

func TestSetResourcePolicySuccess(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcInstance)

	err := svc.SetResourcePolicy(context.Background(), model.ResourcePolicy{Policy: "cG9saWN5"})
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestSetResourcePolicyStoreError(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	mockStore := resourcePolicyStore
	mockStore.Err = errors.New("store failed")
	defer func() {
		mockStore.Err = nil
	}()

	svc := LoggingMiddleware()(svcInstance)
	err := svc.SetResourcePolicy(context.Background(), model.ResourcePolicy{Policy: "cG9saWN5"})
	g.Expect(err).To(gomega.HaveOccurred())

	handled, ok := err.(*HandledError)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(handled.Code).To(gomega.Equal(http.StatusInternalServerError))
}