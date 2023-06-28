/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */

package tasks

import (
	"github.com/onsi/gomega"
	"testing"
)

func TestCreateJWTSigningKey(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	csk := CreateSigningKey{
		JWTSigningKeyPath: "../test/jwt-signing.key",
	}
	err := csk.CreateJWTSigningKey()
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestCreateJWTSigningKeyWithInvalidPath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	csk := CreateSigningKey{
		JWTSigningKeyPath: "../testFolder/jwt-signing.key",
	}
	err := csk.CreateJWTSigningKey()
	g.Expect(err).To(gomega.HaveOccurred())
}
