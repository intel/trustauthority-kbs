/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package crypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"intel/kbs/v1/model"

	"github.com/onsi/gomega"
)

func TestParseJWKPublicKey_RSA(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	jwk := model.JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pk.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pk.E)).Bytes()),
	}

	parsed, err := ParseJWKPublicKey(jwk)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	rsaPub, ok := parsed.(*rsa.PublicKey)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(rsaPub.N.Cmp(pk.N)).To(gomega.Equal(0))
	g.Expect(rsaPub.E).To(gomega.Equal(pk.E))
}

func TestParseJWKPublicKey_EC(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	jwk := model.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(pk.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(pk.Y.Bytes()),
	}

	parsed, err := ParseJWKPublicKey(jwk)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	ecPub, ok := parsed.(*ecdsa.PublicKey)
	g.Expect(ok).To(gomega.BeTrue())
	g.Expect(ecPub.Curve).To(gomega.Equal(elliptic.P256()))
	g.Expect(ecPub.X.Cmp(pk.X)).To(gomega.Equal(0))
	g.Expect(ecPub.Y.Cmp(pk.Y)).To(gomega.Equal(0))
}

func TestParseJWKPublicKey_UnsupportedCurve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	_, err := ParseJWKPublicKey(model.JWK{
		Kty: "EC",
		Crv: "P-384",
		X:   "AQ",
		Y:   "AQ",
	})

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("unsupported ec curve"))
}

func TestParseJWKPublicKey_ECPointNotOnCurve(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	_, err := ParseJWKPublicKey(model.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
	})

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("not on curve"))
}
