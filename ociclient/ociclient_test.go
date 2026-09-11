/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package ociclient

import (
	"testing"

	"github.com/onsi/gomega"
)

func TestInitializeClient(t *testing.T) {
	t.Setenv("OCI_CONFIG_FILE", "../test/resource/oci-config")

	client := NewOCIClient()
	err := client.InitializeClient()

	g := gomega.NewGomegaWithT(t)
	g.Expect(err).To(gomega.BeNil())

	ociClient, ok := client.(*ociClient)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(ociClient.sc).ToNot(gomega.BeNil())
	g.Expect(ociClient.vc).ToNot(gomega.BeNil())
}
