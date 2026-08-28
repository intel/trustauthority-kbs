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
	"fmt"
	"net/http"
	"strings"

	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"intel/kbs/v1/service"
	"intel/kbs/v1/session"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/semver"
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

		if !matchesRCARProtocolVersion(req.Version) {
			log.Errorf("unsupported protocol version %q, expected %q", req.Version, constant.ApiVersionSupported)
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "unsupported protocol version")
			return
		}

		nonce, err := generateNonce(32)
		if err != nil {
			log.WithError(err).Error("failed to generate challenge")
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to generate challenge")
			return
		}

		extraParams, err := challengeExtraParams(req.TEE, req.ExtraParams)
		if err != nil {
			log.WithError(err).Error("failed to negotiate challenge extra params")
			writeProblem(w, http.StatusBadRequest, "Invalid request", err.Error())
			return
		}

		// Persist requested TEE from /auth for use during attestation verification.
		sess := store.CreateWithTEE(nonce, req.TEE)
		http.SetCookie(w, &http.Cookie{
			Name:     rcarSessionCookieName,
			Value:    sess.ID,
			Path:     "/kbs/v0",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return Challenge with nonce and extra_params (no version field per Trustee spec)
		if err := json.NewEncoder(w).Encode(&model.RCARChallenge{
			Nonce:       nonce,
			ExtraParams: extraParams,
		}); err != nil {
			log.WithError(err).Error("failed to encode challenge response")
		}
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
			if err := json.NewEncoder(w).Encode(&model.RCARAttestationResponse{Token: sess.AttestationToken}); err != nil {
				log.WithError(err).Error("failed to encode attestation response")
			}
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
			if handled, ok := err.(*service.HandledError); ok {
				writeProblem(w, handled.Code, "Attestation error", handled.Message)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to generate attestation token")
			return
		}

		// Mark session as attested with the token
		if err := store.StoreAttestationData(cookie.Value, token); err != nil {
			writeProblem(w, http.StatusInternalServerError, "Internal error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(&model.RCARAttestationResponse{Token: token}); err != nil {
			log.WithError(err).Error("failed to encode attestation response")
		}
	}
}

func makeRCARResourceHandler(svc service.Service, store *session.InMemoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		attestationToken, err := resolveResourceAuthSession(r, store)
		if err != nil {
			log.Infof("%v: fallback to bearer token", err)
			attestationToken, err = getBearerToken(r)
			if err != nil {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "missing session cookie and bearer token")
				return
			}
		}

		vars := mux.Vars(r)
		addr, err := model.ParseResourceAddress(vars["repository"], vars["type"], vars["tag"])
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "Invalid resource path", err.Error())
			return
		}

		jweResp, err := svc.GetRCARResource(r.Context(), attestationToken, addr)
		if err != nil {
			log.WithError(err).Error("failed to retrieve resource")
			if handled, ok := err.(*service.HandledError); ok {
				writeProblem(w, handled.Code, "Resource error", handled.Message)
				return
			}
			writeProblem(w, http.StatusInternalServerError, "Internal error", "failed to retrieve resource")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(jweResp); err != nil {
			log.WithError(err).Error("failed to encode resource response")
		}
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
			log.WithError(err).Error("failed to set resource policy")
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

func resolveResourceAuthSession(r *http.Request, store *session.InMemoryStore) (string, error) {
	if cookie, err := r.Cookie(rcarSessionCookieName); err != nil {
		return "", errSessionCookieNotFound
	} else {
		if sess, ok := store.Get(cookie.Value); !ok {
			return "", errSessionNotFound
		} else if !sess.Attested {
			return "", errSessionNotAttested
		} else {
			return sess.AttestationToken, nil
		}
	}
}

func getBearerToken(r *http.Request) (string, error) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" {
		return "", errMissingBearerToken
	}

	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errMissingBearerToken
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errMissingBearerToken
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
	if err := json.NewEncoder(w).Encode(&model.ProblemDetails{
		Type:   model.ProblemTypeAboutBlank,
		Title:  title,
		Status: code,
		Detail: detail,
	}); err != nil {
		log.WithError(err).Error("failed to encode problem details")
	}
}

func matchesRCARProtocolVersion(version string) bool {
	v := strings.TrimSpace(version)
	if v == "" {
		return false
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return false
	}
	required := "v" + constant.ApiVersionSupported
	return semver.Compare(v, required) == 0
}

func generateNonce(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func challengeExtraParams(tee model.Tee, teeParameters map[string]interface{}) (map[string]interface{}, error) {
	if teeParameters == nil {
		return map[string]interface{}{}, nil
	}

	rawAlgorithms, found := teeParameters["supported-hash-algorithms"]
	if !found {
		return map[string]interface{}{}, nil
	}

	list, ok := rawAlgorithms.([]interface{})
	if !ok {
		return nil, fmt.Errorf("expected array for supported-hash-algorithms, found %T", rawAlgorithms)
	}

	supported := make(map[string]struct{}, len(list))
	for _, value := range list {
		s, ok := value.(string)
		if !ok {
			continue
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" {
			supported[s] = struct{}{}
		}
	}

	if len(supported) == 0 {
		return nil, fmt.Errorf("tee does not support any hash algorithms")
	}

	var required string
	switch tee {
	case model.TeeSGX:
		required = "sha256"
	case model.TeeTDX:
		required = "sha512"
	default:
		return nil, fmt.Errorf("unknown tee specified")
	}

	if _, ok := supported[required]; !ok {
		return nil, fmt.Errorf("%s tee does not support %s", strings.ToUpper(string(tee)), required)
	}

	return map[string]interface{}{"selected-hash-algorithm": required}, nil
}
