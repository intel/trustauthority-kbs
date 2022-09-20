/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"
	"intel/amber/kbs/v1/repository/mocks"
	"testing"
)

var mockUserStore *mocks.MockUserStore = mocks.NewFakeUserStore()
var svcJWTTestInstance Service = service{
	asClient:    asClient,
	jwtVerifier: jwtVerifier,
	repository: &repository.Repository{
		UserStore:              mockUserStore,
		KeyStore:               keyStore,
		KeyTransferPolicyStore: keyTransPolicyStore,
	},
	remoteManager: kRemoteManager,
}

func TestAuthTokenCreate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcJWTTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	var users []model.UserInfo
	jwtAuthz := SetupGoguardianForTest()
	request := model.AuthTokenRequest{
		Username: "userAdmin",
		Password: "userAdminPassword",
	}

	mockUserStore.On("Search", mock.Anything).Return(users, nil).Once()
	_, err := svc.CreateAuthToken(context.Background(), request, jwtAuthz)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestAuthTokenCreateWithEmptyRequest(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcJWTTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	jwtAuthz := SetupGoguardianForTest()
	request := model.AuthTokenRequest{}

	mockUserStore.On("Search", mock.Anything).Return(nil, nil).Once()
	_, err := svc.CreateAuthToken(context.Background(), request, jwtAuthz)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestAuthTokenCreateInvalidUsername(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcJWTTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	jwtAuthz := SetupGoguardianForTest()
	request := model.AuthTokenRequest{
		Username: "userAdmin1",
		Password: "userAdminPassword",
	}

	mockUserStore.On("Search", mock.Anything).Return(nil, nil).Once()
	_, err := svc.CreateAuthToken(context.Background(), request, jwtAuthz)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestAuthTokenCreateWithPasswordMismatch(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcJWTTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	jwtAuthz := SetupGoguardianForTest()
	request := model.AuthTokenRequest{
		Username: "userAdmin",
		Password: "invalidPassword",
	}

	mockUserStore.On("Search", mock.Anything).Return(nil, nil).Once()
	_, err := svc.CreateAuthToken(context.Background(), request, jwtAuthz)
	g.Expect(err).To(gomega.HaveOccurred())
}