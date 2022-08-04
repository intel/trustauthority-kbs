/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"intel/amber/kbs/v1/clients/constant"
	consts "intel/amber/kbs/v1/constant"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/service"

	"github.com/go-kit/kit/endpoint"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	Algorithm        = "algorithm"
	KeyLength        = "keyLength"
	CurveType        = "curveType"
	TransferPolicyId = "transferPolicyId"
)

var (
	allowedAlgorithms = map[string]bool{"AES": true, "RSA": true, "EC": true, "aes": true, "rsa": true, "ec": true}
	allowedCurveTypes = map[string]bool{"secp256r1": true, "secp384r1": true, "secp521r1": true, "prime256v1": true}
	allowedKeyLengths = map[int]bool{128: true, 192: true, 256: true, 2048: true, 3072: true, 4096: true, 7680: true}
)

func setKeyHandler(svc service.Service, router *mux.Router, options []httpTransport.ServerOption, auth *model.JwtAuthz) error {

	keyIdExpr := "/keys/" + idReg
	createKeyHandler := httpTransport.NewServer(
		makeCreateKeyEndpoint(svc),
		decodeCreateKeyHTTPRequest,
		encodeCreateKeyHTTPResponse,
		options...,
	)

	router.Handle("/keys", authMiddleware(createKeyHandler, auth)).Methods(http.MethodPost)

	getKeyHandler := httpTransport.NewServer(
		makeRetrieveKeyEndpoint(svc),
		decodeRetrieveHTTPRequest,
		encodeRetrieveHTTPResponse,
		options...,
	)

	router.Handle(keyIdExpr, authMiddleware(getKeyHandler, auth)).Methods(http.MethodGet)

	deleteKeyHandler := httpTransport.NewServer(
		makeDeleteKeyEndpoint(svc),
		decodeDeleteHTTPRequest,
		encodeDeleteHTTPResponse,
		options...,
	)

	router.Handle(keyIdExpr, authMiddleware(deleteKeyHandler, auth)).Methods(http.MethodDelete)

	searchKeysHandler := httpTransport.NewServer(
		makeSearchKeysEndpoint(svc),
		decodeSearchKeysHTTPRequest,
		encodeSearchKeysHTTPResponse,
		options...,
	)

	router.Handle("/keys", authMiddleware(searchKeysHandler, auth)).Methods(http.MethodGet)

	return nil
}

func makeCreateKeyEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(model.KeyRequest)
		return svc.CreateKey(ctx, req)
	}
}

func makeSearchKeysEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		filter := request.(*model.KeyFilterCriteria)
		return svc.SearchKeys(ctx, filter)
	}
}

func makeDeleteKeyEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		id := request.(uuid.UUID)
		return svc.DeleteKey(ctx, id)
	}
}

func makeRetrieveKeyEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		id := request.(uuid.UUID)
		return svc.RetrieveKey(ctx, id)
	}
}

func decodeCreateKeyHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	if r.Header.Get(constant.HTTPHeaderKeyContentType) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidContentTypeHeader.Error())
		return nil, ErrInvalidContentTypeHeader
	}

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	if r.ContentLength == 0 {
		log.Error(ErrEmptyRequestBody.Error())
		return nil, ErrEmptyRequestBody
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var keyCreateReq model.KeyRequest
	err := dec.Decode(&keyCreateReq)
	if err != nil {
		log.WithError(err).Error(ErrJsonDecodeFailed.Error())
		return nil, ErrJsonDecodeFailed
	}

	if err := validateKeyCreateRequest(keyCreateReq); err != nil {
		log.WithError(err).Error(ErrInvalidRequest.Error())
		return nil, ErrInvalidRequest
	}

	return keyCreateReq, nil
}

func decodeRetrieveHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	id := uuid.MustParse(mux.Vars(r)["id"])
	return id, nil
}

func decodeDeleteHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	id := uuid.MustParse(mux.Vars(r)["id"])
	return id, nil
}

func decodeSearchKeysHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	queryKeys := map[string]bool{
		Algorithm:        true,
		KeyLength:        true,
		CurveType:        true,
		TransferPolicyId: true,
	}

	queryValues := r.URL.Query()
	if err := ValidateQueryParamKeys(queryValues, queryKeys); err != nil {
		return nil, err
	}

	criteria, err := getKeyFilterCriteria(queryValues)
	if err != nil {
		log.WithError(err).Error(ErrInvalidFilterCriteria.Error())
		return nil, ErrInvalidFilterCriteria
	}
	return criteria, nil
}

func encodeCreateKeyHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(*model.KeyResponse)

	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	w.WriteHeader(http.StatusCreated)

	return encodeJsonResponse(ctx, w, resp)
}

func encodeRetrieveHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	w.WriteHeader(http.StatusOK)

	return encodeJsonResponse(ctx, w, response)
}

func encodeDeleteHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	w.WriteHeader(http.StatusNoContent)
	return encodeJsonResponse(ctx, w, nil)
}

func encodeSearchKeysHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	//TODO: Change to dictionary instead of returning array
	resp := response.([]*model.KeyResponse)

	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	w.WriteHeader(http.StatusOK)

	return encodeJsonResponse(ctx, w, resp)
}

// validateKeyCreateRequest checks for various attributes in the Create Key request and returns error or nil
func validateKeyCreateRequest(keyCreateReq model.KeyRequest) error {

	algorithm := keyCreateReq.KeyInfo.Algorithm
	if algorithm == "" {
		return errors.New("key algorithm is missing")
	} else if !allowedAlgorithms[algorithm] {
		return errors.New("key algorithm is not supported")
	}

	if strings.ToUpper(algorithm) == consts.CRYPTOALGEC {
		if keyCreateReq.KeyInfo.CurveType == "" {
			return errors.New("curve_type must be provided")
		} else if !allowedCurveTypes[keyCreateReq.KeyInfo.CurveType] {
			return errors.New("curve_type is not supported")
		}
	} else {
		if keyCreateReq.KeyInfo.KeyLength == 0 {
			return errors.New("Key length is missing")
		} else if !allowedKeyLengths[keyCreateReq.KeyInfo.KeyLength] {
			return errors.New("key_length is not supported")
		}
	}

	keyData := keyCreateReq.KeyInfo.KeyData
	kmipKeyID := keyCreateReq.KeyInfo.KmipKeyID
	if keyData != "" {
		if err := ValidatePemEncodedKey(keyData); err != nil {
			return errors.New("key_data must be PEM formatted")
		}
	} else if kmipKeyID != "" {
		if err := ValidateStrings([]string{kmipKeyID}); err != nil {
			return errors.New("kmip_key_id must be a valid string")
		}
	}

	return nil
}

// getKeyFilterCriteria checks for set filter params in the Search request and returns a valid KeyFilterCriteria
func getKeyFilterCriteria(params url.Values) (*model.KeyFilterCriteria, error) {

	criteria := model.KeyFilterCriteria{}

	// algorithm
	if param := strings.TrimSpace(params.Get(Algorithm)); param != "" {
		if !allowedAlgorithms[param] {
			return nil, errors.New("Valid algorithm must be specified")
		}
		criteria.Algorithm = param
	}

	// keyLength
	if param := strings.TrimSpace(params.Get(KeyLength)); param != "" {
		length, err := strconv.Atoi(param)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid keyLength query param value, must be Integer")
		}
		if !allowedKeyLengths[length] {
			return nil, errors.New("Valid keyLength must be specified")
		}
		criteria.KeyLength = length
	}

	// curveType
	if param := strings.TrimSpace(params.Get(CurveType)); param != "" {
		if !allowedCurveTypes[param] {
			return nil, errors.New("Valid curveType must be specified")
		}
		criteria.CurveType = param
	}

	// transferPolicyId
	if param := strings.TrimSpace(params.Get(TransferPolicyId)); param != "" {
		id, err := uuid.Parse(param)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid transferPolicyId query param value, must be UUID")
		}
		criteria.TransferPolicyId = id
	}
	return &criteria, nil
}
