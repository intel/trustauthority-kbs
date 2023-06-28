/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package service

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/repository"
	"intel/amber/kbs/v1/repository/mocks"
	"testing"
)

var userID uuid.UUID
var userStore *mocks.MockUserStore = mocks.NewFakeUserStore()
var svcUserTestInstance Service = service{
	asClient:    asClient,
	jwtVerifier: jwtVerifier,
	repository: &repository.Repository{
		UserStore:              userStore,
		KeyStore:               keyStore,
		KeyTransferPolicyStore: keyTransPolicyStore,
	},
	remoteManager: kRemoteManager,
}

func TestUserCreate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	var request *model.User
	userJson := `{
			"username": "keysAdmin", 
			"password" : "keysAdminPassword", 
			"permissions" : ["keys:create"]
        }`

	json.Unmarshal([]byte(userJson), &request)
	response, err := svc.CreateUser(context.Background(), request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	userID = response.ID
}

func TestUserUpdate(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.UpdateUserRequest{
		ID: userID,
		UpdateUser: &model.User{
			Username: "updatedKeyUsername",
		},
	}

	response, err := svc.UpdateUser(context.Background(), &request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	userID = response.ID
}

func TestUserSearch(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	request := model.UserFilterCriteria{}
	_, err := svc.SearchUser(context.Background(), &request)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	request = model.UserFilterCriteria{
		Username: "keyAdmin",
	}
	_, err = svc.SearchUser(context.Background(), &request)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestUserRetrieve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	_, err := svc.RetrieveUser(context.Background(), userID)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestUserRetrieveInvalidId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())

	tmpId := uuid.New()
	_, err := svc.RetrieveUser(context.Background(), tmpId)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestUserDelete(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	_, err := svc.DeleteUser(context.Background(), userID)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestUserDeleteInvalidId(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	svc := LoggingMiddleware()(svcUserTestInstance)
	g.Expect(svc).NotTo(gomega.BeNil())
	tmpId := uuid.New()
	_, err := svc.DeleteUser(context.Background(), tmpId)
	g.Expect(err).To(gomega.HaveOccurred())
}
