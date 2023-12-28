/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package http

import (
	"context"
	"intel/kbs/v1/model"
	"net/http"

	"intel/kbs/v1/service"

	"github.com/go-kit/kit/endpoint"
	httpTransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

func setGetVersionHandler(svc service.Service, router *mux.Router, options []httpTransport.ServerOption, auth *model.JwtAuthz) error {
	getVersionHandler := httpTransport.NewServer(
		makeGetVersionHTTPEndpoint(svc),
		httpTransport.NopRequestDecoder,
		httpTransport.EncodeJSONResponse,
		options...,
	)

	router.Handle("/version", getVersionHandler).Methods(http.MethodGet)
	return nil
}

func makeGetVersionHTTPEndpoint(svc service.Service) endpoint.Endpoint {
	return func(ctx context.Context, _ interface{}) (interface{}, error) {
		return svc.GetVersion(ctx)
	}
}
