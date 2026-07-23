/*
 *   Copyright (c) 2026 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"intel/kbs/v1/service"
	"intel/kbs/v1/session"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	rcarSessionCookieName = "kbs-session-id"
)

func setRCARHandler(svc service.Service, router *mux.Router, store *session.InMemoryStore, auth *model.JwtAuthz) error {
	router.HandleFunc("/auth", makeRCARAuthHandler(store)).Methods(http.MethodPost)
	router.HandleFunc("/attest", makeRCARAttestHandler(svc, store)).Methods(http.MethodPost)
	router.HandleFunc("/resource/{repository}/{type}/{tag}", makeRCARResourceHandler(svc, store)).Methods(http.MethodGet)
	router.Handle("/resource-policy", authMiddleware(makeRCARResourcePolicyHandler(svc), auth)).Methods(http.MethodPost)
	return nil
}

func makeRCARAuthHandler(store *session.InMemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.RCARAuthRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid request", err.Error())
			return
		}
		if err := req.Validate(); err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid request", err.Error())
			return
		}

		// Validate version against server support (Trustee compatibility)
		// For now, accept 0.4.0 and compatible versions
		if req.Version != constant.ApiVersionV0Supported {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "unsupported protocol version")
			return
		}

		nonce, err := generateNonce(32)
		if err != nil {
			log.WithError(err).Error("failed to generate RCAR nonce")
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to generate challenge")
			return
		}

		// Persist requested TEE from /auth for use during attestation verification.
		sess := store.CreateWithTEE(nonce, req.TEE)
		http.SetCookie(w, &http.Cookie{
			Name:     rcarSessionCookieName,
			Value:    sess.ID,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return Challenge with nonce and extra_params (no version field per Trustee spec)
		extraParams := make(map[string]interface{})
		extraParams["selected-hash-algorithm"] = "sha512"
		_ = json.NewEncoder(w).Encode(&model.RCARChallenge{
			Nonce:       nonce,
			ExtraParams: extraParams,
		})
	}
}

func makeRCARAttestHandler(svc service.Service, store *session.InMemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(rcarSessionCookieName)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "missing session cookie")
			return
		}

		sess, ok := store.Get(cookie.Value)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired session")
			return
		}

		// If session is already attested, return cached token (avoid re-verification)
		if sess.Attested {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(&model.RCARAttestationResponse{Token: sess.AttestationToken})
			return
		}

		var req model.RCARAttestationRequest
		if err := decodeJSONBody(r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid request", err.Error())
			return
		}
		if err := req.Validate(); err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid request", err.Error())
			return
		}

		// Validate nonce binding: session.nonce must match attestation.runtime_data.nonce
		// This prevents replay attacks and ensures attestation is for the correct challenge
		if sess.Nonce != req.RuntimeData.Nonce {
			writeProblem(w, http.StatusBadRequest, "Invalid attestation", "nonce mismatch or session replay")
			return
		}

		// Pass requested TEE hint from /auth to attestation service for robust
		// SGX/TDX evidence routing.
		ctx := service.WithRCARTEEHint(r.Context(), sess.RequestedTEE)
		token, err := svc.VerifyRCARAttestation(ctx, &req)
		if err != nil {
			log.WithError(err).Error("failed to generate attestation token")
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to generate attestation token")
			return
		}

		// Store TEEPubKey from attestation (needed for resource encryption)
		// and mark session as attested with the token
		if err := store.StoreAttestationData(cookie.Value, &req.RuntimeData.TEEPubKey, token); err != nil {
			writeProblem(w, http.StatusInternalServerError, "Internal error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&model.RCARAttestationResponse{Token: token})
	}
}

func makeRCARResourceHandler(svc service.Service, store *session.InMemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := resolveResourceAuthSession(r, store)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", err.Error())
			return
		}
		if !sess.Attested {
			writeProblem(w, http.StatusForbidden, "Forbidden", "session is not attested")
			return
		}

		vars := mux.Vars(r)
		addr, err := model.ParseResourceAddress(vars["repository"], vars["type"], vars["tag"])
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid resource path", err.Error())
			return
		}

		resource, err := svc.GetRCARResource(r.Context(), addr)
		if err != nil {
			if handled, ok := err.(*service.HandledError); ok {
				writeProblem(w, handled.Code, "Resource error", handled.Message)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to retrieve resource")
			return
		}

		jweResp, err := encryptResourceAsFlattenedJWE(sess.TEEPubKey, resource)
		if err != nil {
			log.WithError(err).Error("failed to encrypt resource response")
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to encrypt resource response")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(jweResp)
	}
}

func makeRCARResourcePolicyHandler(svc service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.ResourcePolicy
		if err := decodeJSONBody(r, &req); err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid request", err.Error())
			return
		}

		if err := req.Validate(); err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid request", err.Error())
			return
		}

		if err := svc.SetResourcePolicy(r.Context(), req); err != nil {
			if handled, ok := err.(*service.HandledError); ok {
				writeProblem(w, handled.Code, "Resource policy error", handled.Message)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to set resource policy")
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func resolveResourceAuthSession(r *http.Request, store *session.InMemoryStore) (*session.Session, error) {
	if cookie, err := r.Cookie(rcarSessionCookieName); err == nil {
		sess, ok := store.Get(cookie.Value)
		if !ok {
			return nil, errInvalidOrExpiredSession
		}
		return sess, nil
	}

	bearer, err := getBearerToken(r)
	if err != nil {
		return nil, err
	}

	sess, ok := store.GetByAttestationToken(bearer)
	if !ok {
		return nil, errInvalidBearerToken
	}

	return sess, nil
}

var (
	errMissingResourceAuth     = &resourceAuthError{message: "missing session cookie or bearer token"}
	errInvalidOrExpiredSession = &resourceAuthError{message: "invalid or expired session"}
	errInvalidBearerToken      = &resourceAuthError{message: "invalid bearer token"}
)

type resourceAuthError struct {
	message string
}

func (e *resourceAuthError) Error() string {
	return e.message
}

func getBearerToken(r *http.Request) (string, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" {
		return "", errMissingResourceAuth
	}

	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errMissingResourceAuth
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errMissingResourceAuth
	}

	return token, nil
}

func decodeJSONBody(r *http.Request, out interface{}) error {
	if r.Body == nil || r.ContentLength == 0 {
		return ErrEmptyRequestBody
	}

	// Allow Content-Type with charset suffix (e.g., "application/json; charset=utf-8")
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		return ErrInvalidContentTypeHeader
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func writeProblem(w http.ResponseWriter, code int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(&model.ProblemDetails{
		Type:   model.ProblemTypeAboutBlank,
		Title:  title,
		Status: code,
		Detail: detail,
	})
}

func generateNonce(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generatePlaceholderAttestationToken creates a stub JWT token.
// TODO: Replace with real verifier service call that validates evidence and returns actual JWT.
// Format: header.payload.signature (base64url encoded)
func generatePlaceholderAttestationToken(teePubKey model.JWK) (string, error) {
	// Placeholder JWT: header.payload.signature
	// In production, this would be:
	// 1. Call attestation verifier with evidence
	// 2. Verifier validates and returns real JWT with claims
	// For now, use header.payload format that looks like JWT structure
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	// Minimal payload with placeholder claims
	payloadJSON := []byte(`{"iss":"kbs","aud":"kbs","exp":` +
		`"PLACEHOLDER","iat":"PLACEHOLDER","tee_pubkey":` +
		`{"kty":"` + teePubKey.Kty + `"}}`)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Placeholder signature (not cryptographically valid)
	signature := base64.RawURLEncoding.EncodeToString([]byte(`placeholder_signature`))

	return header + "." + payload + "." + signature, nil
}
