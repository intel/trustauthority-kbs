/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"github.com/onsi/gomega"
	"intel/amber/kbs/v1/clients/as"
	"intel/amber/kbs/v1/config"
	"intel/amber/kbs/v1/jwt"
	"intel/amber/kbs/v1/keymanager"
	"intel/amber/kbs/v1/repository"
	"testing"
)

func TestNewValidService(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	verifier := jwt.NewMockVerifier()
	conf := config.Configuration{BearerTokenValidityInMinutes: 5}
	asClient := as.NewMockClient()
	_, err := NewService(asClient,
		verifier,
		&repository.Repository{},
		&keymanager.RemoteManager{},
		&conf,
	)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestStatusCode(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	he := HandledError{
		Code:    400,
		Message: "Bad Request",
	}
	code := he.StatusCode()
	err := he.Error()

	g.Expect(err).NotTo(gomega.BeNil())
	g.Expect(code).NotTo(gomega.BeNil())
}
