/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kbs

import "intel/kbs/v1/model"

type KeyTransferPolicies []model.KeyTransferPolicy

// KeyTransferPolicy request/response payload
// swagger:parameters KeyTransferPolicy
type KeyTransferPolicy struct {
	// in:body
	// required: true
	Body model.KeyTransferPolicy
}

// KeyTransferPolicyCollection response payload
// swagger:parameters KeyTransferPolicyCollection
type KeyTransferPolicyCollection struct {
	// in:body
	// required: true
	Body KeyTransferPolicies
}

// ---

// swagger:operation POST /key-transfer-policies KeyTransferPolicies CreateKeyTransferPolicy
// ---
//
// description: |
//   Creates a key transfer policy. Only one SGX or TDX key transfer policy can be created at a time. A key
//   transfer policy can be created in the following ways: by providing a list of policy-ids, by providing TDX or SGX attributes, or by providing both a list of policy-ids and TDX or SGX attributes.
//
//   The serialized KeyTransferPolicy Go struct object represents the content of the request body.
//
//    | Attribute                                    | Description |
//    |----------------------------------------------|-------------|
//    | attestation_type                             | An array of attestation-type identifiers that the client must support to get the key. The client must advertise these with the key request, e.g., "SGX," or "TDX." Note that if the key server needs to restrict technologies, it must list technologies that can receive the key. |
//    | mrsigner                                     | An array of measurements of the SGX enclave’s code signing certificate. This is mandatory. The same issuer must be added as a trusted certificate in key server configuration settings. |
//    | isvprodid                                    | An array of (16-bit value) (ISVPRODID). This is mandatory. This is similar to a qualifier for the issuer, so the same issuer (code signing) key can sign separate products. |
//    | mrenclave                                    | An array of enclave measurements that are allowed to retrieve the key (MRENCLAVE). The client must have one of these measurements in the SGX quote. This supports the use case of providing a key only to an SGX enclave that locally enforces the key usage policy. |
//    | isvsvn                                       | Minimum security version number required for Enclave. |
//    | mrsignerseam                                 | An array of measurements of seam module issuer. This is mandatory. |
//    | mrseam                                       | An array of measurements of seam module. This is mandatory. |
//    | mrtd                                         | A array of TD measurements. |
//    | rtmr0                                        | The measurement extended to RTMR0. |
//    | rtmr1                                        | The measurement extended to RTMR1. |
//    | rtmr2                                        | The measurement extended to RTMR2. |
//    | rtmr3                                        | The measurement extended to RTMR3. |
//    | seamsvn                                      | The minimum security version number of seam module. |
//    | enforce_tcb_upto_date                        | The boolean value to enforce an up-to-date TCB. |
//    | policy_ids                                   | A array of TD/Enclave Attestation Policy Ids. |
//
// x-permissions: key-transfer-policies:create
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
//    $ref: "#/definitions/KeyTransferPolicy"
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
//     description: Successfully created the key transfer policy.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicy"
//   '401':
//     description: The request was unauthorized.
//   '400':
//     description: An invalid request body was provided.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies
// x-sgx-sample-call-input: |
//    {
//      "attestation_type": "SGX",
//      "sgx": {
//          "attributes": {
//
//              "mrsigner": ["cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"],
//              "isvprodid": [12],
//              "mrenclave": ["01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"],
//              "isvsvn": 1,
//              "enforce_tcb_upto_date": false
//          },
//          "policy_ids": ["37965f5f-ccaf-4cdc-a356-a8ed5268a5bf", "9846bf40-e380-4842-ae15-1b60996d1190"]
//      }
//    }
// x-sgx-sample-call-output: |
//    {
//      "id": "d0c3f191-80f9-408f-a690-0dde00ba65ac",
//      "created_at": "2021-08-20T06:30:35.085644391Z",
//      "attestation_type": "SGX",
//      "sgx": {
//        "attributes": {
//            "mrsigner": [
//                "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
//            ],
//            "isvprodid": [
//                12
//            ],
//            "mrenclave": [
//                "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
//            ],
//            "isvsvn": 1,
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }
// x-tdx-sample-call-input: |
//    {
//      "attestation_type": "TDX",
//      "tdx": {
//        "attributes": {
//            "mrsignerseam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mrseam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "seamsvn": 0,
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf", "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }
// x-tdx-sample-call-output: |
//    {
//      "id": "cf9adfcf-4bfa-4653-b9b8-2b94beca768f",
//      "created_at": "2021-08-20T05:51:39.588320016Z",
//      "attestation_type": "TDX",
//      "tdx": {
//        "attributes": {
//            "mrsignerseam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mrseam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "seamsvn": 0,
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }

// ---

// swagger:operation GET /key-transfer-policies/{id} KeyTransferPolicies RetrieveKeyTransferPolicy
// ---
//
// description: |
//   Retrieves a key transfer policy.
//   Returns - The serialized KeyTransferPolicy Go struct object that was retrieved.
// x-permissions: key-transfer-policies:search
// security:
// - bearerToken: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the key transfer policy.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the key transfer policy.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicy"
//   '401':
//     description: Request Unauthorized
//   '404':
//     description: KeyTransferPolicy record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies/75d34bf4-80fb-4ca5-8602-a8d82e56b30d
// x-sample-call-output: |
//    {
//      "id": "75d34bf4-80fb-4ca5-8602-a8d82e56b30d",
//      "created_at": "2021-08-20T05:51:39.588320016Z",
//      "attestation_type": "TDX",
//      "tdx": {
//        "attributes": {
//            "mrsignerseam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mrseam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "seamsvn": 0,
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }

// ---

// swagger:operation DELETE /key-transfer-policies/{id} KeyTransferPolicies DeleteKeyTransferPolicy
// ---
//
// description: |
//   Deletes a key transfer policy.
// x-permissions: key-transfer-policies:delete
// security:
// - bearerToken: []
// parameters:
// - name: id
//   description: Unique ID of the key transfer policy.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the key transfer policy.
//   '401':
//     description: Request Unauthorized
//   '404':
//     description: KeyTransferPolicy record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies/75d34bf4-80fb-4ca5-8602-a8d82e56b30d

// ---

// swagger:operation GET /key-transfer-policies KeyTransferPolicies SearchKeyTransferPolicies
// ---
//
// description: |
//   Searches for key transfer policies.
//   Returns - The collection of serialized KeyTransferPolicy Go struct objects.
// x-permissions: key-transfer-policies:search
// security:
// - bearerToken: []
// produces:
//  - application/json
// parameters:
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully retrieved the key transfer policies.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/KeyTransferPolicies"
//   '401':
//     description: Request Unauthorized
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/key-transfer-policies
// x-sample-call-output: |
//  [
//    {
//      "id": "d0c3f191-80f9-408f-a690-0dde00ba65ac",
//      "created_at": "2021-08-20T06:30:35.085644391Z",
//      "attestation_type": "SGX",
//      "sgx": {
//        "attributes": {
//            "mrsigner": [
//                "cd171c56941c6ce49690b455f691d9c8a04c2e43e0a4d30f752fa5285c7ee57f"
//            ],
//            "isvprodid": [
//                12
//            ],
//            "mrenclave": [
//                "01c60b9617b2f96e53cb75ef01e0dccea3afc7b7992697eabb8f714b2ccd1953"
//            ],
//            "isvsvn": 1,
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    },
//    {
//      "id": "cf9adfcf-4bfa-4653-b9b8-2b94beca768f",
//      "created_at": "2021-08-20T05:51:39.588320016Z",
//      "attestation_type": "TDX",
//      "tdx": {
//        "attributes": {
//            "mrsignerseam": [
//                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//            ],
//            "mrseam": [
//                "0f3b72d0f9606086d6a7800e7d50b82fa6cb5ec64c7210353a0696c1eef343679bf5b9e8ec0bf58ab3fce10f2c166ebe"
//            ],
//            "seamsvn": 0,
//            "mrtd": [
//                "cf656414fc0f49b23e2ae64b6f23b82901e2206aab36b671e360ebd414899dab51bbb60134bbe6ad8dcc70b995d9dc50"
//            ],
//            "rtmr0": "b90abd43736381b12fc9b038924c73e31c8371674905e7fcb7941d69fe59d30eda3adb9e41b878151e756fb05ad13d14",
//            "rtmr1": "a53c98b16f0de470338e7f072d9c5fcef6171327ec6c78b842e637251b1de6e37354c47fb68de27ef14bb67caf288d9b",
//            "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//            "enforce_tcb_upto_date": false
//        },
//        "policy_ids": [
//            "37965f5f-ccaf-4cdc-a356-a8ed5268a5bf",
//            "9846bf40-e380-4842-ae15-1b60996d1190"
//        ]
//      }
//    }
//  ]
