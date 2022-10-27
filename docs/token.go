/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import "intel/amber/kbs/v1/model"

// token request payload
// swagger:parameters AuthTokenRequest
type AuthTokenRequest struct {
	// Specifies user credentials for whom a JWT authentication needs to be issued
	// required: true
	// in:body
	Body model.AuthTokenRequest
}

// ---
//
// swagger:operation POST /token Token CreateAuthToken
// ---
//
// description: |
//   Creates a JWT for the specified user in the request
//
//   The serialized AuthTokenRequest Go struct object represents the content of the request body.
//
//    | Attribute  | Description |
//    |------------|-------------|
//    | username   | Name of the user for which the token is being requested. This user should already be created using /users POST API |
//    | password   | The password of the user for which the token is being requested |
//
//
// produces:
// - application/jwt
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/AuthTokenRequest"
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/jwt
// responses:
//   '200':
//     description: Successfully issued authentication token for specified user.
//     content:
//       application/jwt
//   '400':
//     description: Invalid request body provided or User with given name does not exist or Password does not match for the given user
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/token
// x-sample-call-input: |
//    {
//            "username": "testUser",
//            "password": "testUserPassword"
//    }
// x-sample-call-output: |
//    eyJhbGciOiJQUzM4NCIsImtpZCI6InNlY3JldC1pZCIsInR5cCI6IkpXVCJ9.eyJFeHRlbnNpb25zIjpudWxsLCJHcm91cHMiOm51bGwsIklEIjoiMzQzNmU1MjgtMzQ5My00Y2Y0LWIxZGQtNDU4MTg0ZjI2MDA2IiwiTmFtZSI6ImFkbWluIiwiYXVkIjpbIiJdLCJleHAiOjE2NjMyOTc4OTMsImlhdCI6MTY2MzI5NDI5MywibmJmIjoxNjYzMjk0MjkzLCJzY29wZSI6WyJrZXlzOnNlYXJjaCIsImtleXM6Y3JlYXRlIiwia2V5czpkZWxldGUiLCJrZXlfdHJhbnNmZXJfcG9saWNpZXM6Y3JlYXRlIiwia2V5X3RyYW5zZmVyX3BvbGljaWVzOnNlYXJjaCIsImtleV90cmFuc2Zlcl9wb2xpY2llczpkZWxldGUiLCJ1c2VyczpkZWxldGUiLCJ1c2VyczpzZWFyY2giLCJ1c2VyczpjcmVhdGUiLCJ1c2Vyczp1cGRhdGUiXSwic3ViIjoiMzQzNmU1MjgtMzQ5My00Y2Y0LWIxZGQtNDU4MTg0ZjI2MDA2In0.iQQWBlc3yp3eyl9mGdhCvECRQ1DspHEawS7uNjMz7d3GnxDuAFRMAc2KJJxxMtRMh5rJXerRoCyBHKA_MlHNg7-bveGBrTIr5mZzFA_ynrx4mmR9POtFFHRA7EO1Wd3B1WniTGyqLgdW80Obmzhnnx_sbirkece9HYAZb9NhQGYsTgWF4Mz9K6Jgu8T-qSbgjtKABAt7QPi_YPuyJVJQ4IV_2ZfsLZFA5p4UKBI-UqIGP7O27xrX7SFfqA6hsSNadp4FGchZBwiv5CR1RCP0CloJOVbjegiCr_8KDdm9-Noo8feYfrqNjm4vUYUDHtG89s-s3K0jpp8-JiMCZoT7yLiMd4Sel4KUNL6jx6yE6Jz4-RW-S0SF556qFbhy0INo-YsXNExg2xzFEYJGyiIuUmVUnlVHHkvcXizLf5z9bJPL3pw_WVKz4m-FSzGLxF6g-yzrE_BNh3Qclhqic5SS4gwJUpBifG72PSTarIx7Q7BNDpHdXxWUQxhzfeY0gd1y
//
// ---
