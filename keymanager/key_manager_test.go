/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"intel/kbs/v1/config"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/ociclient"
	"testing"

	"github.com/onsi/gomega"
)

func TestNewKmipKeyManagerNegative(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	cfg := &config.Configuration{}
	_, errObj := NewKeyManager(cfg)
	g.Expect(errObj).To(gomega.HaveOccurred())

	cfg.KeyManager = constant.KmipKeyManager
	_, errObj = NewKeyManager(cfg)
	g.Expect(errObj).To(gomega.HaveOccurred())
}

func TestNewVaultKeyManager(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	cfg := &config.Configuration{}
	_, errObj := NewKeyManager(cfg)
	g.Expect(errObj).To(gomega.HaveOccurred())

	cfg.KeyManager = constant.VaultKeyManager
	_, errObj = NewKeyManager(cfg)
	g.Expect(errObj).To(gomega.BeNil())
}

func TestNewOciKeyManager(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	cfg := &config.Configuration{}
	_, errObj := NewKeyManager(cfg)
	g.Expect(errObj).To(gomega.HaveOccurred())

	cfg.KeyManager = constant.OCIKeyManager
	mockClient := ociclient.NewMockOCIClient()
	mockClient.On("InitializeClient").Return(nil).Once()

	keyManager, errObj := newKeyManager(cfg, func() ociclient.OCIClient {
		return mockClient
	})
	g.Expect(errObj).To(gomega.BeNil())
	g.Expect(keyManager).To(gomega.BeAssignableToTypeOf(&OCIManager{}))
	mockClient.AssertExpectations(t)
}
