// Key Broker Service
//
// The Key Broker Service enables key distribution using platform trust to authorize key transfers. By retaining image decryption keys,
// unauthorized access can be prevented, even from within the Cloud Service Provider. It interfaces with a backend key management system(KMIP)
// to create, delete and retrieve keys, while providing a user defined policy for key retrieval based on Intel® hardware root of trust.
// License: Copyright (C) 2022 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version:0.1.0
//  Host: kbs.com:9443
//  BasePath: /kbs/v1
//
//
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
//swagger:meta
package kbs
