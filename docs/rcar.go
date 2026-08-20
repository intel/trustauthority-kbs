/*
 * Copyright(C) 2026 Intel Corporation. All Rights Reserved.
 */
package kbs

import "intel/kbs/v1/model"

// RCARAuth request payload
// swagger:parameters RCARAuthRequest
//
// Trust establishment step. Client requests a challenge nonce.
type RCARAuthRequest struct {
	// in:body
	// required: true
	Body model.RCARAuthRequest
}

// RCARAuth response payload
// swagger:response RCARAuthResponse
type RCARAuthResponse struct {
	// in:body
	Body model.RCARChallenge
}

// RCARAttest request payload
// swagger:parameters RCARAttestRequest
type RCARAttestRequest struct {
	// in:body
	// required: true
	Body model.RCARAttestationRequest
}

// RCARAttest response payload
// swagger:response RCARAttestResponse
type RCARAttestResponse struct {
	// in:body
	Body model.RCARAttestationResponse
}

// RCARResource response payload
// swagger:response RCARResourceResponse
type RCARResourceResponse struct {
	// in:body
	Body model.JWEFlattened
}

// RCARResourcePolicy request payload
// swagger:parameters RCARResourcePolicyRequest
type RCARResourcePolicyRequest struct {
	// in:body
	// required: true
	Body model.ResourcePolicy
}

// RCARProblem error payload
// swagger:response RCARProblem
type RCARProblem struct {
	// in:body
	Body model.ProblemDetails
}

// ---
// swagger:operation POST /kbs/v0/auth RCAR RCARAuth
// ---
// description: |
//   Starts RCAR protocol negotiation and returns a nonce challenge.
//
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/RCARAuthRequest"
// responses:
//   '200':
//     $ref: "#/responses/RCARAuthResponse"
//   '400':
//     $ref: "#/responses/RCARProblem"
//   '401':
//     $ref: "#/responses/RCARProblem"
//   '500':
//     $ref: "#/responses/RCARProblem"

// ---
// swagger:operation POST /kbs/v0/attest RCAR RCARAttest
// ---
// description: |
//   Submits attestation evidence and runtime data to receive an attestation token.
//
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: Cookie
//   description: Session cookie returned by /kbs/v0/auth (kbs-session-id).
//   in: header
//   required: true
//   type: string
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/RCARAttestationRequest"
// responses:
//   '200':
//     $ref: "#/responses/RCARAttestResponse"
//   '400':
//     $ref: "#/responses/RCARProblem"
//   '401':
//     $ref: "#/responses/RCARProblem"
//   '500':
//     $ref: "#/responses/RCARProblem"

// ---
// swagger:operation GET /kbs/v0/resource/{repository}/{type}/{tag} RCAR RCARGetResource
// ---
// description: |
//   Retrieves a resource encrypted as flattened JWE for the attested workload.
//
// produces:
// - application/json
// parameters:
// - name: repository
//   in: path
//   required: true
//   type: string
// - name: type
//   in: path
//   required: true
//   type: string
// - name: tag
//   in: path
//   required: true
//   type: string
// - name: Authorization
//   description: Optional Bearer attestation token if session cookie is not used.
//   in: header
//   required: false
//   type: string
// responses:
//   '200':
//     $ref: "#/responses/RCARResourceResponse"
//   '400':
//     $ref: "#/responses/RCARProblem"
//   '401':
//     $ref: "#/responses/RCARProblem"
//   '500':
//     $ref: "#/responses/RCARProblem"

// ---
// swagger:operation POST /kbs/v0/resource-policy RCAR RCARSetResourcePolicy
// ---
// description: |
//   Sets a Rego resource policy used to authorize RCAR resource access.
//
// produces:
// - application/json
// consumes:
// - application/json
// security:
// - bearerToken: []
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/ResourcePolicy"
// responses:
//   '200':
//     description: Resource policy stored successfully.
//   '400':
//     $ref: "#/responses/RCARProblem"
//   '401':
//     $ref: "#/responses/RCARProblem"
//   '500':
//     $ref: "#/responses/RCARProblem"
