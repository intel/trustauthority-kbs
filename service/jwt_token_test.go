/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */

package service

import (
	"context"
	"github.com/onsi/gomega"
	jwtStrategy "github.com/shaj13/go-guardian/v2/auth/strategies/jwt"
	"github.com/stretchr/testify/mock"
	"intel/kbs/v1/config"
	"intel/kbs/v1/model"
	"intel/kbs/v1/repository"
	"intel/kbs/v1/repository/mocks"
	"testing"
)

var mockUserStore *mocks.MockUserStore = mocks.NewFakeUserStore()
var svcJWTTestInstance Service = service{
	itaApiClient:           itaClientConnector,
	itaTokenVerifierClient: itaClientConnector,
	repository: &repository.Repository{
		UserStore:              mockUserStore,
		KeyStore:               keyStore,
		KeyTransferPolicyStore: keyTransPolicyStore,
	},
	remoteManager: kRemoteManager,
	config:        &config.Configuration{BearerTokenValidityInMinutes: 5},
}
var keeper = jwtStrategy.StaticSecret{
	ID:        "secret-id",
	Secret:    []byte("testSecret@#12"),
	Algorithm: jwtStrategy.HS384,
}

var jwtAuthz, _ = SetupAuthZ(&keeper)

func TestAuthTokenCreate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcJWTTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	var users []model.UserInfo
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

	request := model.AuthTokenRequest{}

	mockUserStore.On("Search", mock.Anything).Return(nil, nil).Once()
	_, err := svc.CreateAuthToken(context.Background(), request, jwtAuthz)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestAuthTokenCreateInvalidUsername(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcJWTTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

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

	request := model.AuthTokenRequest{
		Username: "userAdmin",
		Password: "invalidPassword",
	}

	mockUserStore.On("Search", mock.Anything).Return(nil, nil).Once()
	_, err := svc.CreateAuthToken(context.Background(), request, jwtAuthz)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestAuthTokenCreateWithInvalidJwtAuthz(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcJWTTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	jwtAuthz, _ := SetupAuthZ(&jwtStrategy.StaticSecret{
		Secret:    nil,
		ID:        "",
		Algorithm: "",
	})
	request := model.AuthTokenRequest{
		Username: "userAdmin",
		Password: "userAdminPassword",
	}

	mockUserStore.On("Search", mock.Anything).Return(nil, nil).Once()
	_, err := svc.CreateAuthToken(context.Background(), request, jwtAuthz)
	g.Expect(err).To(gomega.HaveOccurred())
}
