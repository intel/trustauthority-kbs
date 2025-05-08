/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kbs

import (
	"intel/kbs/v1/model"
)

type KeyResponses []model.KeyResponse

// Key request payload
// swagger:parameters KeyRequest
type KeyRequest struct {
	// in:body
	// required: true
	Body model.KeyRequest
}

// Key response payload
// swagger:parameters KeyResponse
type KeyResponse struct {
	// in:body
	// required: true
	Body model.KeyResponse
}

// KeyCollection response payload
// swagger:parameters KeyCollection
type KeyCollection struct {
	// in:body
	Body KeyResponses
}

// KeyTransfer response payload
// swagger:parameters KeyTransferResponse
type KeyTransferResponse struct {
	// in:body
	// required: true
	Body model.KeyTransferResponse
}

// Key update payload
// swagger:parameters KeyUpdateRequest
type KeyUpdateRequest struct {
	// in:body
	// required: true
	Body model.KeyUpdateRequest
}

// ---
// swagger:operation POST /keys Keys CreateKey
// ---
//
// description: |
//   Creates or registers a key.
//
//   The serialized KeyRequest Go struct object represents the content of the request body.
//
//    | Attribute          | Description |
//    |--------------------|-------------|
//    | key_information    | A JSON object containing all the required information about a key. |
//    | transfer_policy_id | The unique identifier of the transfer policy to be applied to this key. |
//
//   The serialized KeyInformation Go struct object represents the content of the key_information field.
//
//    | Attribute          | Description |
//    |--------------------|-------------|
//    | algorithm          | The encryption algorithm used to create or register a key.  The supported algorithms are AES, RSA, and EC. |
//    | key_length         | The key length used to create a key. Supported key lengths are 128,192,256 bits for AES and 2048,3072,4096,7680 bits for RSA. This parameter must be provided only for the AES and RSA algorithms. |
//    | curve_type         | The elliptic curve used to create a key. The supported curves are secp256r1, secp384r1, prime256v1 and secp521r1. This parameter must be provided only for the EC algorithm. |
//    | key_data           | The Base64 encoded private key to be registered.  It is only supported if the key is created locally. |
//    | kmip_key_id        | The unique KMIP identifier of the key to be registered.  It is only supported if the key is created on a KMIP server. |
//    | oci_compartment_id | The Oracle Cloud ID (OCID) of the compartment where you want to create the secret. |
//    | oci_key_id         | The Oracle Cloud ID (OCID) of the master encryption key that is used to encrypt the secret. You must specify a symmetric key to encrypt the secret during import to the vault. You cannot encrypt secrets with asymmetric keys. Furthermore, the key must exist in the vault that you specify. |
//    | oci_secret_name    | A user-friendly name for the secret. Secret names should be unique within a vault. Avoid entering confidential information. Valid characters are uppercase or lowercase letters, numbers, hyphens, underscores, and periods. |
//    | oci_vault_id       | The Oracle Cloud ID (OCID) of the vault where you want to create the secret. |
//
// x-permissions: keys:create
// security:
// - bearerToken: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/KeyRequest"
// - name: Content-Type
//   description: Content-Type header.
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// - name: Accept
//   description: Accept header.
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '201':
//     description: The key was successfully created or registered.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyResponse"
//   '401':
//     description: The request was unauthorized.
//   '400':
//     description: An invalid request body was provided.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys
// x-sample-call-input: |
//    {
//        "key_information": {
//            "algorithm": "AES",
//            "key_length": 256
//        }
//    }
// x-sample-call-output: |
//    {
//        "key_information": {
//            "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//            "algorithm": "AES",
//            "key_length": 256
//        },
//        "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9",
//        "transfer_link": "/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer",
//        "created_at": "2020-09-23T11:16:26.738467277Z"
//    }

// ---

// swagger:operation GET /keys/{id} Keys RetrieveKey
// ---
//
// description: |
//   Retrieves a key.
//   Returns - The serialized KeyResponse Go struct object that was retrieved.
// x-permissions: keys:search
// security:
// - bearerToken: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: The unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept
//   description: Accept header.
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: The key was successfully retrieved.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyResponse"
//   '401':
//     description: The request was unauthorized.
//   '404':
//     description: The key record was not found.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e
// x-sample-call-output: |
//    {
//        "key_information": {
//            "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//            "algorithm": "AES",
//            "key_length": 256
//        },
//        "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9",
//        "transfer_link": "/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer",
//        "created_at": "2020-09-23T11:16:26.738467277Z"
//    }

// ---

// swagger:operation POST keys/{id} Keys TransferKey
// ---
//
// description: |
//   Releases a wrapped AES key with the public key provided in the request.
//   Returns - The serialized KeyTransferResponse Go struct object that was retrieved.
// x-permissions: keys:transfer
// security:
// - bearerToken: []
// produces:
// - application/json
// consumes:
// - application/x-pem-file
// parameters:
// - name: id
//   description: Unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/x-pem-file
// - name: Accept
//   description: Accept header.
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: The key was successfully transferred.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferResponse"
//   '404':
//     description: The key record was not found
//   '415':
//     description: Invalid Content-Type/Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e
// x-sample-call-input: |
//   -----BEGIN PUBLIC KEY-----
//   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjtGIk8SxD+OEiBpP2/T
//   JUAF0upwuKGMk6wH8Rwov88VvzJrVm2NCticTk5FUg+UG5r8JArrV4tJPRHQyvqK
//   wF4NiksuvOjv3HyIf4oaOhZjT8hDne1Bfv+cFqZJ61Gk0MjANh/T5q9vxER/7TdU
//   NHKpoRV+NVlKN5bEU/NQ5FQjVXicfswxh6Y6fl2PIFqT2CfjD+FkBPU1iT9qyJYH
//   A38IRvwNtcitFgCeZwdGPoxiPPh1WHY8VxpUVBv/2JsUtrB/rAIbGqZoxAIWvijJ
//   Pe9o1TY3VlOzk9ASZ1AeatvOir+iDVJ5OpKmLnzc46QgGPUsjIyo6Sje9dxpGtoG
//   QQIDAQAB
//   -----END PUBLIC KEY-----
// x-sample-call-output: |
//   {
//      "wrapped_key": "sKCE8YFz9DON8FghjavoHJCMec0+cPwj5pGxK35FXuMAQaxxECQH/vWTuUdK4eHBgk1/FMcfbSnjPRvIqANYQBWwNWfNrQVQ+NBa+PCP5FstjCjFUUIPYC2ei/taZtnp4RXx25eiljprmGcuboEAP359+J4tjkKJeuppxRnxA7u5ewjB+C4vhOpyWkOyP5Iio6RqXzWVVz6Usn2QIjVArpjLR0vk/HuB2TUCMoohxu3UloXUUeDAeWWGToQ9E9Pqc8jLNKvHlksZzZHuzSAaDz7q601LxD+BFKF2EvuWCVLS/hrScBL68SkB/nvsZIiGYxHbk3mzhFGEGFEVfkAx+g=="
//   }
// ---

// swagger:operation DELETE /keys/{id} Keys DeleteKey
// ---
//
// description: |
//   Deletes a key.
// x-permissions: keys:delete
// security:
// - bearerToken: []
// parameters:
// - name: id
//   description: Unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: The key was successfully deleted.
//   '401':
//     description: Request Unauthorized.
//   '404':
//     description: The key record was not found.
//   '500':
//     description: Internal server error.
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e

// ---

// swagger:operation GET /keys Keys SearchKey
// ---
//
// description: |
//   Searches for keys. At least one of the query parameters must be provided.
//
//   Returns - The collection of serialized KeyResponse Go struct objects.
// x-permissions: keys:search
// security:
// - bearerToken: []
// produces:
//  - application/json
// parameters:
// - name: algorithm
//   description: Key algorithm.
//   in: query
//   type: string
//   required: false
//   enum: [AES, RSA, EC, aes, rsa, ec]
// - name: keyLength
//   description: Key length.
//   in: query
//   type: integer
//   required: false
//   enum: [128, 192, 256, 2048, 3072, 4096, 7680]
// - name: curveType
//   description: Elliptic Curve name.
//   in: query
//   type: string
//   required: false
//   enum: [secp256r1, secp384r1, secp521r1, prime256v1]
// - name: transferPolicyId
//   description: Unique identifier of the transfer policy.
//   in: query
//   type: string
//   format: uuid
//   required: false
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the keys.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyResponses"
//   '401':
//     description: Request Unauthorized
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys?algorithm=aes
// x-sample-call-output: |
//    [
//        {
//            "key_information": {
//                "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//                "algorithm": "AES",
//                "key_length": 256
//            },
//            "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f83d9",
//            "transfer_link": "/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer",
//            "created_at": "2020-09-23T11:16:26.738467277Z"
//        }
//    ]

// ---

// swagger:operation PUT /keys/{id} Keys UpdateKey
// ---
//
// description: |
//   Updates a key with the key transfer policy.
//
//   The serialized KeyRequest Go struct object represents the content of the request body.
//
//    | Attribute          | Description |
//    |--------------------|-------------|
//    | transfer_policy_id | The unique identifier of the transfer policy to be applied to this key. |
//
//
// x-permissions: keys:update
// security:
// - bearerToken: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/KeyUpdateRequest"
// - name: Content-Type
//   description: Content-Type header.
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// - name: Accept
//   description: Accept header.
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '201':
//     description: The key was successfully updated.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyResponse"
//   '401':
//     description: Request Unauthorized.
//   '400':
//     description: An invalid request body was provided.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e
// x-sample-call-input: |
//    {
//        "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f84f8",
//    }
// x-sample-call-output: |
//    {
//        "key_information": {
//            "id": "fc0cc779-22b6-4741-b0d9-e2e69635ad1e",
//            "algorithm": "AES",
//            "key_length": 256
//        },
//        "transfer_policy_id": "3ce27bbd-3c5f-4b15-8c0a-44310f0f84f8",
//        "transfer_link": "/kbs/v1/keys/fc0cc779-22b6-4741-b0d9-e2e69635ad1e/transfer",
//        "created_at": "2020-09-23T11:16:26.738467277Z"
//    }
