/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package keymanager

import (
	"github.com/onsi/gomega"
	"intel/kbs/v1/config"
	"intel/kbs/v1/constant"
	"testing"
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
