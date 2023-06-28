/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"github.com/onsi/gomega"
	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/keymanager"
	"intel/amber/kbs/v1/repository"
	"testing"
)

func TestNewValidService(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	verifier := jwt.NewMockVerifier()
	asClient := as.NewMockClient()
	_, err := NewService(asClient,
		verifier,
		&repository.Repository{},
		&keymanager.RemoteManager{})
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
