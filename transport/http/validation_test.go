/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"github.com/onsi/gomega"
	"testing"
)

func TestValidatePemEncodedKeyFunc(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	err := ValidatePemEncodedKey("invalidKey%%%###")
	g.Expect(err).To(gomega.HaveOccurred())

	err = ValidatePemEncodedKey(" ")
	g.Expect(err).To(gomega.HaveOccurred())

	in := "AQABALX8TwtlMn052rcxr9BOiyZvuqx1om2ZaP8ZtIv0BDwQ2v8rJ2avAovHO5Ux+Rv5UNsQKtKeUK7GqFiPefzoZofd4/nLstGvLNWei0fa45rkKk+3UwqnXjc8RP4hKbd4QTWiETWqN5BryHHWEKZjsM53SQriB8GyyyNC7M2kppJmOb1O7vNUZC3xjxCt5NEog8PpAD09eMLjJCM9N9+uFqOgg8EBpqdMvUhPyjacTqabZWdxd0GdwDJZdKGbfZy0o8Hi1zcs5u/NwxOIMf5E9CtCWKnhnA55nG5adbzil7DA8sq1OA8Ss3zvGoljip4s7exH+naO9Wxwt8HCDxbLEaU="
	err = ValidatePemEncodedKey(in)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

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
