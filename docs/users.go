/*
 * Copyright(C) 2023 Intel Corporation. All Rights Reserved.
 */
package kbs

import "intel/kbs/v1/model"

// user request payload
// swagger:parameters User
type User struct {
	// Describes component user account details and associated roles
	// in:body
	// required: true
	Body model.User
}

// user response payload
// swagger:parameters UserResponse
type UserResponse struct {
	// in:body
	// required: true
	Body model.UserResponse
}

// ---
//
// swagger:operation POST /users User CreateUser
// ---
//
// description: |
//   Creates a user with the given username, password, and API permissions.
//
//   The serialized User Go struct object represents the content of the request body.
//
//    | Attribute   | Description |
//    |-------------|-------------|
//    | username    | The name of the user. It must be less than 256 characters. |
//    | password    | The password of the user. It must be between 8 and 72 characters. |
//    | permissions | The KBS REST API permissions in ["{KBS_API}:{CRUD_permissions}"] format. The supported KBS APIs are users, keys, and key-transfer-policies. The supported CRUD_permissions are create, delete, search, and update. |
//
// x-permissions: users:create
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
//    "$ref": "#/definitions/User"
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
//   '200':
//     description: Successfully created a user.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '400':
//     description: An invalid request body was provided.
//   '401':
//     description: The request was unauthorized.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/users
// x-sample-call-input: |
//    {
//       "username": "testUser",
//       "password": "testUserPassword",
//       "permissions": ["users:create", "keys:create"]
//    }
// x-sample-call-output: |
//	  {
//	    "id": "9acad9da-4ef0-4865-9426-f9c5a8be4d62",
//	    "created_at": "2022-09-16T03:13:09.503698068Z",
//	    "updated_at": "0001-01-01T00:00:00Z",
//	    "username": "keysAdmin",
//	    "permissions": [
//	    "users:create",
//	    "keys:create"
//	   ]
//	  }

// ---

// swagger:operation GET /users/{id} User RetrieveUser
// ---
//
// description: |
//   Retrieves user information for the provided user ID.
//   Returns - The serialized UserResponse Go struct object that was retrieved.
// x-permissions: users:search
// security:
// - bearerToken: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: The unique ID of the user.
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
//     description: The user information was successfully retrieved.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '401':
//     description: The request was unauthorized.
//   '404':
//     description: The user record was not found.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/users/9acad9da-4ef0-4865-9426-f9c5a8be4d62
// x-sample-call-output: |
//	  {
//	    "id": "9acad9da-4ef0-4865-9426-f9c5a8be4d62",
//	    "created_at": "2022-09-16T03:13:09.503698068Z",
//	    "updated_at": "0001-01-01T00:00:00Z",
//	    "username": "keysAdmin",
//	    "permissions": [
//	    "users:create",
//	    "keys:create"
//	   ]
//	  }

// ---

// swagger:operation DELETE /users/{id} User DeleteUser
// ---
//
// description: |
//   Deletes a user account and associated roles.
// x-permissions: users:delete
// security:
// - bearerToken: []
// parameters:
// - name: id
//   description: The unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '401':
//     description: The request was unauthorized.
//   '204':
//     description: The user was successfully deleted.
//   '404':
//     description: The user record was not found.
//   '500':
//     description: Internal server error.
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/users/9acad9da-4ef0-4865-9426-f9c5a8be4d62

// ---

// swagger:operation GET /users User SearchUser
// ---
//
// description: |
//   Searches for users. At least one of the query parameters must be provided.
//
//   Returns - The collection of serialized UserResponse Go struct objects.
// x-permissions: users:search
// security:
// - bearerToken: []
// produces:
//  - application/json
// parameters:
// - name: username
//   description: The name of the user for which to search.
//   in: query
//   type: string
//   required: false
// - name: Accept
//   description: Accept header.
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: The users were successfully retrieved.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '401':
//     description: The request was unauthorized.
//   '400':
//     description: Invalid values for request params.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/users?username=keysAdmin
// x-sample-call-output: |
//	  {
//	    "id": "9acad9da-4ef0-4865-9426-f9c5a8be4d62",
//	    "created_at": "2022-09-16T03:13:09.503698068Z",
//	    "updated_at": "0001-01-01T00:00:00Z",
//	    "username": "keysAdmin",
//	    "permissions": [
//	    "users:create",
//	    "keys:create"
//	   ]
//	  }
// ---
//

// swagger:operation PUT /users/{id} User UpdateUser
// ---
//
// description: |
//   Updates a user with the username, password, and API permissions provided in the body of the request for a user with the ID in the path parameter.
//
//   The serialized User Go struct object represents the content of the request body.
//
//    | Attribute   | Description |
//    |-------------|-------------|
//    | username    | Name of the user. |
//    | password    | The password of the user. |
//    | permissions | The KBS REST API permissions in ["{KBS_API}:{CRUD_permissions}"] format. The supported KBS API's are users, keys, and key-transfer-policies. The supported CRUD_permissions are create, delete, search. and update|
//
// x-permissions: users:update
// security:
// - bearerToken: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: id
//   description: The unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/User"
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
//   '200':
//     description: Successfully created a user.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '400':
//     description: An invalid request body was provided.
//   '401':
//     description: The request was unauthorized.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/users/9acad9da-4ef0-4865-9426-f9c5a8be4d62
// x-sample-call-input: |
//    {
//       "username": "updatedUsername",
//       "password": "testUserPassword",
//       "permissions": ["users:create", "keys:create"]
//    }
// x-sample-call-output: |
//	  {
//	    "id": "9acad9da-4ef0-4865-9426-f9c5a8be4d62",
//	    "created_at": "2022-09-16T03:13:09.503698068Z",
//	    "updated_at": "0001-01-01T00:00:00Z",
//	    "username": "updatedUsername",
//	    "permissions": [
//	    "users:create",
//	    "keys:create"
//	   ]
//	  }

// ---
