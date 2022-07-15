/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package keymanager

import (
	"github.com/onsi/gomega"
	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/constant"
	"testing"
)

func TestNewKmipKeyManager(t *testing.T) {
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
