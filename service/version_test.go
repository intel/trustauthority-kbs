/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"github.com/onsi/gomega"
	"testing"
)

func TestVersion(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	_, err := svc.GetVersion(context.Background())
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
