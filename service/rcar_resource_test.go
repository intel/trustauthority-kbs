/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"intel/kbs/v1/model"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
)

// clearResourcePolicy resets the shared mock resource policy store back to nil.
func clearResourcePolicy() {
	resourcePolicyStore.LastPolicy = nil
	resourcePolicyStore.Err = nil
}

// setResourcePolicy sets the shared mock resource policy store to the given Rego text.
func setResourcePolicy(regoText string) {
	resourcePolicyStore.LastPolicy = &model.ResourcePolicy{
		Policy: base64.StdEncoding.EncodeToString([]byte(regoText)),
	}
}

func rcarServiceInstance() service {
	svc, ok := svcInstance.(service)
	if !ok {
		panic("svcInstance is not concrete service")
	}
	return svc
}

func TestGetRawRCARResource_NoPolicyAllowsAccess(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	clearResourcePolicy()
	defer clearResourcePolicy()

	keyID := uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2")
	kmipKeyManager.On("TransferKey", mock.Anything).Return([]byte("test-secret"), nil).Once()

	ctx := context.Background()
	result, err := rcarServiceInstance().getRawRCARResource(ctx, nil, &model.ResourceAddress{Repository: "default", Type: "key", Tag: keyID.String()})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).NotTo(gomega.BeEmpty())
}

func TestGetRawRCARResource_PolicyDeniesAccess(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	setResourcePolicy(`
package policy
default allow = false
`)
	defer clearResourcePolicy()

	keyID := uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2")
	ctx := context.Background()
	_, err := rcarServiceInstance().getRawRCARResource(ctx, nil, &model.ResourceAddress{Repository: "default", Type: "key", Tag: keyID.String()})
	g.Expect(err).To(gomega.HaveOccurred())

	handled, ok := err.(*HandledError)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(handled.Code).To(gomega.Equal(http.StatusForbidden))
}

func TestGetRawRCARResource_PolicyAllowsSpecificResourcePath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	setResourcePolicy(`
package policy
default allow = false
allow {
		data.plugin == "resource"
		data["resource-path"][0] == "default"
		data["resource-path"][1] == "key"
		data["resource-path"][2] == "ee37c360-7eae-4250-a677-6ee12adce8e2"
}
`)
	defer clearResourcePolicy()

	keyID := uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2")
	kmipKeyManager.On("TransferKey", mock.Anything).Return([]byte("test-secret"), nil).Once()
	ctx := context.Background()
	result, err := rcarServiceInstance().getRawRCARResource(ctx, nil, &model.ResourceAddress{Repository: "default", Type: "key", Tag: keyID.String()})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).NotTo(gomega.BeEmpty())
}

func TestGetRawRCARResource_PolicyDeniesWrongResourcePath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	setResourcePolicy(`
package policy
default allow = false
allow {
		data.plugin == "resource"
		data["resource-path"][0] == "default"
		data["resource-path"][1] == "key"
		data["resource-path"][2] == "ee37c360-7eae-4250-a677-6ee12adce8e2"
}
`)
	defer clearResourcePolicy()

	ctx := context.Background()
	_, err := rcarServiceInstance().getRawRCARResource(ctx, nil, &model.ResourceAddress{Repository: "default", Type: "key", Tag: uuid.New().String()})
	g.Expect(err).To(gomega.HaveOccurred())

	handled, ok := err.(*HandledError)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(handled.Code).To(gomega.Equal(http.StatusForbidden))
}

func TestGetRawRCARResource_PolicyEvaluatedWithTokenClaims(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	setResourcePolicy(`
package policy
default allow = false
allow {
		input.attester_type == "sgx"
		input.attester_tcb_status == "OK"
}
`)
	defer clearResourcePolicy()

	verifiedClaims := jwtlib.MapClaims{"attester_type": "sgx", "attester_tcb_status": "OK"}
	ctx := context.Background()

	keyID := uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2")
	kmipKeyManager.On("TransferKey", mock.Anything).Return([]byte("test-secret"), nil).Once()
	result, err := rcarServiceInstance().getRawRCARResource(ctx, verifiedClaims, &model.ResourceAddress{Repository: "default", Type: "key", Tag: keyID.String()})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result).NotTo(gomega.BeEmpty())
}

func TestGetRawRCARResource_PolicyDeniesWhenClaimMismatch(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	setResourcePolicy(`
package policy
default allow = false
allow {
		input.attester_type == "sgx"
		input.attester_tcb_status == "OK"
}
`)
	defer clearResourcePolicy()

	verifiedClaims := jwtlib.MapClaims{"attester_type": "tdx", "attester_tcb_status": "OK"}
	ctx := context.Background()

	_, err := rcarServiceInstance().getRawRCARResource(ctx, verifiedClaims, &model.ResourceAddress{Repository: "default", Type: "key", Tag: uuid.New().String()})
	g.Expect(err).To(gomega.HaveOccurred())

	handled, ok := err.(*HandledError)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(handled.Code).To(gomega.Equal(http.StatusForbidden))
}
