/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"github.com/onsi/gomega"
	"testing"
)

func TestValidateSha256HexString(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	err := ValidateSha256HexString("invalidsha")
	g.Expect(err).To(gomega.HaveOccurred())

	err = ValidateSha256HexString("791dbb8e2630e360d59a90e39ce36ca5876061565c3dfe018ab3e74d900147c5")
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestValidateSha384HexString(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	err := ValidateSha384HexString("invalidsha")
	g.Expect(err).To(gomega.HaveOccurred())

	err = ValidateSha384HexString("44b101aaafe03bcadb88d05853916cf8f3bc51300a4429ae95ef0f7749b036bfa54d1bd92df5391f74c63d1e5703ac2e")
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
func TestValidateStrings(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	in := []string{"test"}
	err := ValidateStrings(in)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	in = []string{"@340-1"}
	err = ValidateStrings(in)
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestValidateQueryParamKeys(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	queryValues := make(map[string][]string)

	queryValues["algorithm"] = []string{"RSA"}
	queryValues["keyLength"] = []string{"3072"}
	queryKeys := map[string]bool{
		Algorithm:        true,
		KeyLength:        true,
		CurveType:        true,
		TransferPolicyId: true,
	}

	err := ValidateQueryParamKeys(queryValues, queryKeys)
	g.Expect(err).NotTo(gomega.HaveOccurred())

}
