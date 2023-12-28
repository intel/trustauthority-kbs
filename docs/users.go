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
//   Creates a user with the given username, password and API permissions
//
//   The serialized User Go struct object represents the content of the request body.
//
//    | Attribute   | Description |
//    |-------------|-------------|
//    | username    | Name of the user |
//    | password    | The password of the user |\
//    | permissions | The KBS REST API permissions in ["{KBS_API}:{CRUD_permissions}"] format. Supported KBS API's are users, keys, key-transfer-policies. Supported CRUD_permissions are create, delete, search and update|
//
// x-permissions: users:create
// security:
// - bearerAuth: []
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
//     - application/json
// responses:
//   '200':
//     description: Successfully created a user.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '400':
//     description: Invalid request body provided
//   '401':
//     description: Request Unauthorized
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
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
//   Retrieves a user information for the provided user ID.
//   Returns - The serialized UserResponse Go struct object that was retrieved.
// x-permissions: users:search
// security:
// - bearerAuth: []
// produces:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the user.
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
//     description: Successfully retrieved the user information.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '401':
//     description: Request Unauthorized
//   '404':
//     description: User record not found
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
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
// - bearerAuth: []
// parameters:
// - name: id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '401':
//     description: Request Unauthorized
//   '204':
//     description: Successfully deleted the user.
//   '404':
//     description: user record not found
//   '500':
//     description: Internal server error
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/users/9acad9da-4ef0-4865-9426-f9c5a8be4d62

// ---

// swagger:operation GET /users User SearchUser
// ---
//
// description: |
//   Searches for users with a given set of filter criterias.
//   Returns - The collection of serialized UserResponse Go struct objects.
// x-permissions: users:search
// security:
// - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: username
//   description: the name of the user want to search.
//   in: query
//   type: string
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
//     description: Successfully retrieved the users.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '401':
//     description: Request Unauthorized
//   '400':
//     description: Invalid values for request params
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
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
//   Updates a user with username, password and API permissions provided in the body of the request for a user with ID in the path parameter
//
//   The serialized User Go struct object represents the content of the request body.
//
//    | Attribute   | Description |
//    |-------------|-------------|
//    | username    | Name of the user |
//    | password    | The password of the user |\
//    | permissions | The KBS REST API permissions in ["{KBS_API}:{CRUD_permissions}"] format. Supported KBS API's are users, keys, key-transfer-policies. Supported CRUD_permissions are create, delete, search and update|
//
// x-permissions: users:update
// security:
// - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: id
//   description: Unique ID of the user.
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
//     - application/json
// responses:
//   '200':
//     description: Successfully created a user.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/UserResponse"
//   '400':
//     description: Invalid request body provided
//   '401':
//     description: Request Unauthorized
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
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
