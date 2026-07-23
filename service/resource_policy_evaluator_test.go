/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/onsi/gomega"
)

const allowAllPolicy = `
package policy

default allow = false

allow {
	true
}
`

const denyAllPolicy = `
package policy

default allow = false
`

const allowByTEEPolicy = `
package policy

default allow = false

allow {
	input.attester_type == "sgx"
}
`

const allowByResourcePathPolicy = `
package policy

default allow = false

allow {
	data.plugin == "resource"
	data["resource-path"][0] == "default"
	data["resource-path"][1] == "key"
	data["resource-path"][2] == "ee37c360-7eae-4250-a677-6ee12adce8e2"
}
`

const allowByQueryPolicy = `
package policy

default allow = false

allow {
	data.plugin == "external"
	data.query.version == "1.0.0"
}
`

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestRegoEvaluator_AllowAll(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	eval, err := buildEvaluatorFromPolicy(b64(allowAllPolicy))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(eval).NotTo(gomega.BeNil())

	allowed, err := eval.Allow(context.Background(), ResourcePolicyInput{
		Plugin:               "resource",
		ResourcePathSegments: []string{"default", "key", "abc"},
		ResourcePath:         "default/key/abc",
		TokenClaims:          map[string]interface{}{"attester_type": "tdx"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(allowed).To(gomega.BeTrue())
}

func TestRegoEvaluator_DenyAll(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	eval, err := buildEvaluatorFromPolicy(b64(denyAllPolicy))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	allowed, err := eval.Allow(context.Background(), ResourcePolicyInput{
		Plugin:               "resource",
		ResourcePathSegments: []string{"default", "key", "abc"},
		ResourcePath:         "default/key/abc",
		TokenClaims:          map[string]interface{}{"attester_type": "tdx"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(allowed).To(gomega.BeFalse())
}

func TestRegoEvaluator_AllowByTEE(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	eval, err := buildEvaluatorFromPolicy(b64(allowByTEEPolicy))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// sgx should be allowed
	allowed, err := eval.Allow(context.Background(), ResourcePolicyInput{ResourcePath: "default/key/abc", TokenClaims: map[string]interface{}{"attester_type": "sgx"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(allowed).To(gomega.BeTrue())

	// tdx should be denied
	allowed, err = eval.Allow(context.Background(), ResourcePolicyInput{ResourcePath: "default/key/abc", TokenClaims: map[string]interface{}{"attester_type": "tdx"}})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(allowed).To(gomega.BeFalse())
}

func TestRegoEvaluator_AllowByResourcePath(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	eval, err := buildEvaluatorFromPolicy(b64(allowByResourcePathPolicy))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	allowed, err := eval.Allow(context.Background(), ResourcePolicyInput{
		Plugin:               "resource",
		ResourcePathSegments: []string{"default", "key", "ee37c360-7eae-4250-a677-6ee12adce8e2"},
		ResourcePath:         "default/key/ee37c360-7eae-4250-a677-6ee12adce8e2",
		TokenClaims:          map[string]interface{}{"attester_type": "sgx"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(allowed).To(gomega.BeTrue())

	allowed, err = eval.Allow(context.Background(), ResourcePolicyInput{
		Plugin:               "resource",
		ResourcePathSegments: []string{"default", "key", "other-key"},
		ResourcePath:         "default/key/other-key",
		TokenClaims:          map[string]interface{}{"attester_type": "sgx"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(allowed).To(gomega.BeFalse())
}

func TestRegoEvaluator_AllowByQuery(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	eval, err := buildEvaluatorFromPolicy(b64(allowByQueryPolicy))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	allowed, err := eval.Allow(context.Background(), ResourcePolicyInput{
		Plugin: "external",
		Query:  map[string]string{"version": "1.0.0"},
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(allowed).To(gomega.BeTrue())
}

func TestBuildEvaluatorFromPolicy_NilWhenEmpty(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	eval, err := buildEvaluatorFromPolicy("")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(eval).To(gomega.BeNil())
}

func TestBuildEvaluatorFromPolicy_InvalidBase64(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	_, err := buildEvaluatorFromPolicy("@@notbase64@@")
	g.Expect(err).To(gomega.HaveOccurred())
}

func TestParseTokenClaims(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	// Minimal JWT: header.payload.sig (base64url encoded)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"attester_type":"tdx","attester_tcb_status":"OK"}`))
	token := header + "." + payload + ".fakesig"

	claims, err := parseTokenClaims(token)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(claims["attester_type"]).To(gomega.Equal("tdx"))
	g.Expect(claims["attester_tcb_status"]).To(gomega.Equal("OK"))
}

func TestParseTokenClaims_Empty(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	claims, err := parseTokenClaims("")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(claims).To(gomega.BeNil())
}
