/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"github.com/onsi/gomega"
	"intel/kbs/v1/clients/ita"
	"intel/kbs/v1/config"
	"intel/kbs/v1/keymanager"
	"intel/kbs/v1/repository"
	"testing"
)

func TestNewValidService(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	conf := config.Configuration{}
	itaClient := ita.NewMockClient()
	conf = config.Configuration{BearerTokenValidityInMinutes: 5}
	_, err := NewService(itaClient, itaClient,
		&repository.Repository{},
		&keymanager.RemoteManager{},
		&conf)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestStatusCode(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	he := HandledError{
		Code:    400,
		Message: "Bad Request",
	}
	err := he.Error()
	g.Expect(err).NotTo(gomega.BeNil())
}
