/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"github.com/onsi/gomega"
	"testing"
)

func TestCreateTLSSigningKeyCert(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tlsCs := TLSKeyAndCert{
		TLSCertPath: "../test/tls.crt",
		TLSKeyPath:  "../test/tls.key",
		TlsSanList:  "localhost",
	}
	err := tlsCs.GenerateTLSKeyandCert()
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestCreateTLSSigningKeyCertWithInvalidCertPath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tlsCs := TLSKeyAndCert{
		TLSCertPath: "../test/invalidFolder/tls.crt",
		TLSKeyPath:  "../test/tls.key",
	}
	err := tlsCs.GenerateTLSKeyandCert()
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestCreateTLSSigningKeyCertWithInvalidKeyPath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tlsCs := TLSKeyAndCert{
		TLSCertPath: "../test/tls.crt",
		TLSKeyPath:  "../test/invalidFolder/tls.key",
	}
	err := tlsCs.GenerateTLSKeyandCert()
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestGenerateAndStoreCertificateInvalidSanList(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	tlsCs := TLSKeyAndCert{
		TLSCertPath: "../test/tls.crt",
		TLSKeyPath:  "../test/tls.key",
		TlsSanList:  "invalid,::value",
	}

	err := tlsCs.GenerateTLSKeyandCert()
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
