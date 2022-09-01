/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"github.com/onsi/gomega"
	"testing"
)

func TestCreateTLSSigningKeyCert(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tlsCs := TLSKeyAndCert{
		TLSCertPath: "..//test/tls.crt",
		TLSKeyPath:  "..//test/tls.key",
		TlsSanList:  "localhost",
	}
	err := tlsCs.GenerateTLSKeyandCert()
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestCreateTLSSigningKeyCertWithInvalidPath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tlsCs := TLSKeyAndCert{
		TLSCertPath: "../test/invalidFolder/tls.crt",
		TLSKeyPath:  "../test/invalidFolder/tls.key",
	}
	err := tlsCs.GenerateTLSKeyandCert()
	g.Expect(err).To(gomega.HaveOccurred())
}
