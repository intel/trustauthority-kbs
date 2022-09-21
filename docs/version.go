/*
 *  Copyright (C) 2022 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

//
// swagger:operation GET /version Version GetVersion
// ---
// description: |
//   GetVersion is used to get the version of the application.
//   Returns - The version of the application.
//
// produces:
//   - text/plain
// responses:
//   '200':
//     description: Successfully retrieved the version.
//     content: application/json
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/version
// x-sample-call-output: |
//   {"Service Name": "Key Broker Service",
//    "Version": "v0.0.0-0f0162ea",
//    "Build Date": "2022-03-08T12:17:18+0000"}
