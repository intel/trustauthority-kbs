/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
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
