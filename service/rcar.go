/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package service

import (
	"context"
	"net/http"
	"time"

	"intel/kbs/v1/model"

	"github.com/sirupsen/logrus"
)

type rcarTEEHintCtxKey struct{}
type rcarAttestationTokenCtxKey struct{}

// WithRCARTEEHint stores a trusted tee hint from the RCAR auth session.
func WithRCARTEEHint(ctx context.Context, tee model.Tee) context.Context {
	if tee == "" {
		return ctx
	}
	return context.WithValue(ctx, rcarTEEHintCtxKey{}, tee)
}

func rcarTEEHintFromContext(ctx context.Context) (model.Tee, bool) {
	v := ctx.Value(rcarTEEHintCtxKey{})
	tee, ok := v.(model.Tee)
	if !ok {
		return "", false
	}
	return tee, tee == model.TeeSGX || tee == model.TeeTDX
}

// WithRCARAttestationToken stores the attested session JWT token in the context.
func WithRCARAttestationToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, rcarAttestationTokenCtxKey{}, token)
}

func rcarAttestationTokenFromContext(ctx context.Context) (string, bool) {
	v := ctx.Value(rcarAttestationTokenCtxKey{})
	token, ok := v.(string)
	return token, ok && token != ""
}

func (mw loggingMiddleware) VerifyRCARAttestation(ctx context.Context, req *model.RCARAttestationRequest) (string, error) {
	var err error
	defer func(begin time.Time) {
		logrus.Tracef("VerifyRCARAttestation took %s since %s", time.Since(begin), begin)
		if err != nil {
			logrus.WithError(err)
		}
	}(time.Now())

	token, err := mw.next.VerifyRCARAttestation(ctx, req)
	return token, err
}

// VerifyRCARAttestation transforms Trustee RCAR attestation payloads into ITA v2
// request bodies and obtains an attestation token from ITA.
func (svc service) VerifyRCARAttestation(ctx context.Context, req *model.RCARAttestationRequest) (string, error) {
	if req == nil {
		return "", &HandledError{Code: http.StatusBadRequest, Message: "request cannot be nil"}
	}
	if err := req.Validate(); err != nil {
		return "", &HandledError{Code: http.StatusBadRequest, Message: err.Error()}
	}

	teeType := model.Tee("")
	if hint, ok := rcarTEEHintFromContext(ctx); ok {
		teeType = hint
	}

	reqBody, effectiveTEEType, requestID, err := buildAttestRequest(req, teeType)
	if err != nil {
		return "", &HandledError{Code: http.StatusBadRequest, Message: err.Error()}
	}

	token, err := svc.getTokenV2FromRequest(reqBody, requestID, "ITA RCAR attest request failed")
	if err != nil {
		if effectiveTEEType == model.TeeTDX {
			return "", &HandledError{Code: http.StatusBadGateway, Message: err.Error()}
		}
		return "", &HandledError{Code: http.StatusBadGateway, Message: err.Error()}
	}
	return token, nil
}
