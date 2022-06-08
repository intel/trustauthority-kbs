/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package http

import (
	"context"
	"encoding/json"
	"net/http"

	"intel/amber/kbs/v1/clients/constant"
	"intel/amber/kbs/v1/model"
	"intel/amber/kbs/v1/service"

	"github.com/go-kit/kit/endpoint"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func setKeyTransferHandler(svc service.Service, router *mux.Router, options []httpTransport.ServerOption) error {

	keyIdExpr := "/keys/" + idReg

	transferKeyHandler := httpTransport.NewServer(
		makeTransferKeyHTTPEndpoint(svc),
		decodeTransferKeyHTTPRequest,
		encodeTransferKeyHTTPResponse,
		options...,
	)

	router.Handle(keyIdExpr+"/transfer", transferKeyHandler).Methods(http.MethodPost)

	return nil
}

func makeTransferKeyHTTPEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(service.TransferKeyRequest)
		return svc.TransferKey(ctx, req)
	}
}

func decodeTransferKeyHTTPRequest(_ context.Context, r *http.Request) (interface{}, error) {

	var keyTransferReq model.KeyTransferRequest

	if r.Header.Get(constant.HTTPHeaderKeyAccept) != constant.HTTPHeaderValueApplicationJson {
		log.Error(ErrInvalidAcceptHeader.Error())
		return nil, ErrInvalidAcceptHeader
	}

	id := uuid.MustParse(mux.Vars(r)["id"])
	attestType := r.Header.Get(constant.HTTPHeaderKeyAttestationType)

	if attestType != "" {
		if r.Header.Get(constant.HTTPHeaderKeyContentType) != constant.HTTPHeaderValueApplicationJson {
			log.Error(ErrInvalidContentTypeHeader.Error())
			return nil, ErrInvalidContentTypeHeader
		}
		if attestType != "SGX" && attestType != "TDX" {
			log.Error(ErrInvalidAttestationType.Error())
			return nil, ErrInvalidAttestationType
		}

		if r.ContentLength == 0 {
			log.Error(ErrEmptyRequestBody.Error())
			return nil, ErrEmptyRequestBody
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		err := dec.Decode(&keyTransferReq)
		if err != nil {
			log.WithError(err).Error(ErrJsonDecodeFailed.Error())
			return nil, ErrJsonDecodeFailed
		}
	}

	req := service.TransferKeyRequest{
		KeyId:              id,
		AttestationType:    attestType,
		KeyTransferRequest: &keyTransferReq,
	}

	return req, nil
}

func encodeTransferKeyHTTPResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(*service.TransferKeyResponse)

	header := w.Header()
	header.Set(constant.HTTPHeaderKeyContentType, constant.HTTPHeaderValueApplicationJson)
	header.Set(constant.HTTPHeaderKeyAttestationType, resp.AttestationType)
	w.WriteHeader(http.StatusOK)

	if resp.KeyTransferResponse == nil {
		return encodeJsonResponse(ctx, w, resp.SignedNonce)
	}

	return encodeJsonResponse(ctx, w, resp.KeyTransferResponse)
}
