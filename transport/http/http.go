/*
 *   Copyright (c) 2024 Intel Corporation
 *   All rights reserved.
 *   SPDX-License-Identifier: BSD-3-Clause
 */

package http

import (
	"context"
	"encoding/json"
	"fmt"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/shaj13/libcache/fifo"
	log "github.com/sirupsen/logrus"
	"intel/kbs/v1/config"
	"intel/kbs/v1/constant"
	"intel/kbs/v1/model"
	"intel/kbs/v1/service"
	"net/http"
)

func NewHTTPHandler(svc service.Service, conf *config.Configuration, jwtAuthz *model.JwtAuthz) (http.Handler, error) {
	r := mux.NewRouter()
	r.SkipClean(true)

	options := []httpTransport.ServerOption{
		httpTransport.ServerErrorEncoder(errorEncoder),
	}

	{
		prefix := r.PathPrefix(fmt.Sprintf("/%s/%s", constant.ServiceName, constant.ApiVersion))
		sr := prefix.Subrouter()

		myHandlers := []func(service.Service, *mux.Router, []httpTransport.ServerOption, *model.JwtAuthz) error{
			setGetVersionHandler,
			setKeyHandler,
			setKeyTransferPolicyHandler,
			setKeyTransferHandler,
			setCreateAuthTokenHandler,
			setUserHandler,
		}

		for _, handler := range myHandlers {
			if err := handler(svc, sr, options, jwtAuthz); err != nil {
				return nil, err
			}
		}
	}

	h := handlers.RecoveryHandler(
		handlers.RecoveryLogger(log.StandardLogger()),
		handlers.PrintRecoveryStack(true),
	)(
		handlers.CombinedLoggingHandler(
			log.StandardLogger().Writer(),
			r,
		),
	)

	return h, nil
}

func encodeJsonResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if response != nil {
		// Send JSON response back to the client application
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			log.WithError(err).Errorf("Error from Handler: %s\n", err.Error())
			return err
		}
	}

	return nil
}

func errorEncoder(_ context.Context, err error, w http.ResponseWriter) {
	if handledError, ok := err.(*service.HandledError); ok {
		w.WriteHeader(handledError.Code)
	} else {
		w.WriteHeader(errToCode(err))
	}
	if err := json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()}); err != nil {
		log.WithError(err).Error("Failed to encode error")
	}
}

func errToCode(err error) int {
	switch err {
	case ErrInvalidRequest, ErrJsonDecodeFailed, ErrEmptyRequestBody, ErrReadRequestFailed, ErrTooManyQueryParams, ErrInvalidQueryParam, ErrInvalidFilterCriteria, ErrBase64DecodeFailed, ErrInvalidAttestationType:
		return http.StatusBadRequest
	case ErrInvalidContentTypeHeader, ErrInvalidAcceptHeader:
		return http.StatusUnsupportedMediaType
	}
	return http.StatusInternalServerError
}

type errorWrapper struct {
	Error string `json:"error"`
}
