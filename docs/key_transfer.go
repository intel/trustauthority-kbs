package kbs

import "intel/kbs/v1/service"

// TransferKey request payload
// swagger:parameters TransferKeyRequest
type TransferKeyRequest struct {
	// in:body
	// required: true
	Body service.TransferKeyRequest
}

// TransferKey response payload
// swagger:parameters TransferKeyResponse
type TransferKeyResponse struct {
	// in:body
	// required: true
	Body service.TransferKeyResponse
}

// ---
// swagger:operation POST /keys/{id}/transfer TransferKey TransferKey
// ---
//
// description: |
//   Transfers a wrapped secret and wrapped SWK.
//
//   The serialized KeyRequest Go struct object that represents the content of the request body.
//
//    | Attribute          | Description |
//    |--------------------|-------------|
//    | attestation_token  | Attestation token received from Intel Trust Authority. This is the only attribute required to retrieve the key in passport mode   |
//    | quote              | TEE quote from workload. This attribute is required to retrieve the key in background mode. |
//    | nonce              | Verifier nonce from Intel Trust Authority. This is a serialized Go struct "VerifierNonce" in the Intel Trust Authority connector. |
//    | user_data          | TEE held data in an attestation token. It is the public key created in the workload that is used to wrap the SWK key. |
//    | nonce              | Verifier nonce from Intel Trust Authority. This is a serialized Go struct "VerifierNonce" in the Intel Trust Authority connector. |
//
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: id
//   description: The unique ID of the key.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/TransferKeyRequest"
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
//     description: The key was successfully transferred.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/TransferKeyResponse"
//   '401':
//     description: Failed to authenticate the attestation token.
//   '404':
//     description: The key record was not found.
//   '400':
//     description: An invalid request body was provided.
//   '415':
//     description: Invalid Accept Header in the request.
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://kbs.com:9443/kbs/v1/keys
// x-sample-call-input: |
//		{
//			"attestation_token": "eyJhbGciOiJQUzM4NCIsImprdSI6Imh0dHBzOi8vYW1iZXItcG9jLXVzZXIxLnByb2plY3QtYW1iZXItc21hcy5jb20vY2VydHMiLCJraWQiOiJkN2VjN2RlZjY3NzVhMjdiZTRkNGUzODY1NGZhMWNlOGM1ZTI5MjI2YzgzZTIwNTQwMGU0NDExNzI4YjA2YTQ2ZDY5MDU5ZWU2NGM5NmY0MjE0NTU2YWNmYmQzYjcwNDYiLCJ0eXAiOiJKV1QifQ.eyJzZ3hfbXJlbmNsYXZlIjoiODNmNGU4MTk4NjFhZGVmNmZmYjJhNDg2NWVmZWE5MzM3YjkxZWQzMGZhMzM0OTFiMTdmMGQ1ZDllODIwNDQxMCIsInNneF9tcnNpZ25lciI6IjgzZDcxOWU3N2RlYWNhMTQ3MGY2YmFmNjJhNGQ3NzQzMDNjODk5ZGI2OTAyMGY5YzcwZWUxZGZjMDhjN2NlOWUiLCJzZ3hfaXN2cHJvZGlkIjowLCJzZ3hfaXN2c3ZuIjowLCJzZ3hfcmVwb3J0X2RhdGEiOiJkODNlZWE5MTI2ZTQ2YTA1OTA1ZDY2YTA4ZTEzZjg0ODdkMWRlNDhhNzQ2NzllOTJhMmIwZWU3MjViNTVkMWY1MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInNneF9pc19kZWJ1Z2dhYmxlIjpmYWxzZSwic2d4X2NvbGxhdGVyYWwiOnsicWVpZGNlcnRoYXNoIjoiYjJjYTcxYjhlODQ5ZDVlNzk5NDUxYjRiZmU0MzE1OWEwZWU1NDgwMzJjZWNiMmMwZTQ3OWJmNmVlM2YzOWZkMSIsInFlaWRjcmxoYXNoIjoiZjQ1NGRjMWI5YmQ0Y2UzNmMwNDI0MWUyYzhjMzdhMmFlMjZiMDc3ZjJjNjZiOTE5ODQzMzY1MzE4YTU5MzMyYyIsInFlaWRoYXNoIjoiNGRjZDUwMWVjZTdhNzY3NWJmMDFjZDEyM2RmYmZiZDEwYzEyOTk4ZWRkNGYyMDE5ZjMxNGUxZTM1OTE4NmI5ZSIsInF1b3RlaGFzaCI6IjFhMjExYzNjZjdlYmI3ZDRjZjBmYTM1OGM4YjQzZWYxOGFkYjk3MDgzNGMxMjcxYjUyMjg5OWNmNzA3MThjY2QiLCJ0Y2JpbmZvY2VydGhhc2giOiJiMmNhNzFiOGU4NDlkNWU3OTk0NTFiNGJmZTQzMTU5YTBlZTU0ODAzMmNlY2IyYzBlNDc5YmY2ZWUzZjM5ZmQxIiwidGNiaW5mb2NybGhhc2giOiJmNDU0ZGMxYjliZDRjZTM2YzA0MjQxZTJjOGMzN2EyYWUyNmIwNzdmMmM2NmI5MTk4NDMzNjUzMThhNTkzMzJjIiwidGNiaW5mb2hhc2giOiJlYzFjZWYzNzNiNWIyOThkN2JkZTM4NTI5NTE0NWQ5MmU0ZGU0MTZkMGQ1OTRlYzQ1NWVmNGU3YTMyMzUwMGY0In0sImF0dGVzdGVyX2hlbGRfZGF0YSI6IkFRQUJBRVdweWYxOWUyZUFSQ1BxL2wwN0N2a1BHSW9KSys0OHREdHY1c0I1V3N3QjJPWTYzcVN4YitEeE9yWi9iNTRCTkY2eGVTLytzN1c4MXorNVJLUXdtZXdJYWdlWlpCeVdIcDB4czZlT25ob0dNcGRERUhGaElmcDlhbjVlNHdQOHRub2FZeXplRDY2SjVXZ2QzZ1grc0J2NkdMMUJCUnE0TTFiTlZzbFhjejR3M3M0eFdXTzJDTGZnU3BJMWpBVG9FaHhMeHRhK2U1SXN0bjR2MmhYc3VFbWtlU0w1TkhyY2Z5N0FtUGhGSVNVb3l5Slo5MTIxakVrVy95bC9vR2JKZWdmZVd3RDMxNkFmNjlnYXdGQ08yOXhqdXBuZlFhN1hDUitZckIyWFRJcURxSEFibzFmUWFicmRHM0hseUlpdnlheUZZejZtb3p0djBWTW5vQWZVRnpaNzBadmNlZmNJMkhBQ28ycUlKbWF0aHlvaXN1d0gzYVowT2pjZzUzclNCc1RLOVFONGp6eVlrSWcwRGwwcHJqenJJSXlUeGVyRGYrL1IvWURUTnk5S0M2T0NsdVplMHhMbVl3RmZPY1BNcjZ0YVdWRVBETTdLOFJtdWI1SHcwMm1DUFhOaE5qT1RyUHhNNXdxckxiWDV4SjVmSnMzM3dsdjVlK1hWaTJhZ2pRPT0iLCJ2ZXJpZmllcl9ub25jZSI6eyJ2YWwiOiJlSE5wV0hoUFJHcEdVa2hDUzBwclMyTTBUMFpOYVRGMVRsb3paWFpIYlVsNVVuRm5PVFJ6Y1RkTGJISlhlbGd2YWtKNVNqTXlNelkxWldKR1NFNXZlbU51VUVNclRWSlJiVE5UVUVwMWExbHZhVFUyTkZFOVBRPT0iLCJpYXQiOiJNakF5TkMwd01TMHhNQ0F5TWpvME1EbzFOQ0FyTURBd01DQlZWRU09Iiwic2lnbmF0dXJlIjoiZHo5UUUram9JNTJwUFI0aTdaSlpFSHNYblNJbUtWUlMrWEJxWmcyS0M2WWxJZ3lGckp6UnNnK3FFaWZWSWJid3IwZmk3U01od1hObWc0VUdrYXVTc3JveThVbVdYeitQRStEbmJPN3VHSWdFSjVkdTAxMUdDQTNzbWlOWlZnd1FMV0lWamFaRmoyZkxqcVE0YTI4c2R5TU9tUUZjaFU0ODVjcGt1anZ1cUdPYzFlOXdyNVM0UEM1czBCSzJGZFlMNXk1MU1sNXhncWJTTVlXRC9majErM0xJOTExY2xjWDhmeVMyYWRxZkdaZ01LSE9LOTdacXppOWgvUkJvOGZIVDkrc1dBc0JwUXE0N1MzczlPTGhPOUpRUGR6K1hjKzczSEYxY0Nwa2dTczc2VndJdUhoaVhDOUhDR25VRHNZVjllK290S2RGSlpTRnB0ZWNUM2VkQzB5N0dGai9oeG9INzR1NC9yOTBMR0tQbk1KQkV1WklibzZWdDVwQnNzT05YdVUrUGZ4eTVUZkZFQWt1dUlzTm0xdlF3SmlhOW01UEZaQUd4RjFIWFNCWER1ZXJwUW9kbnd0dEltSTU1djNMMHJ6cXBjUjBJM0E4bk9ORHRvZEc4ZWhEbXpza0RhL3JxUnovOFNrU1QwaXY1VzRCSHp5dUFtS1pxRWxTRXY3bWoifSwiYXR0ZXN0ZXJfdGNiX3N0YXR1cyI6Ik91dE9mRGF0ZSIsImF0dGVzdGVyX3RjYl9kYXRlIjoiMjAyMS0xMS0xMFQwMDowMDowMFoiLCJhdHRlc3Rlcl9hZHZpc29yeV9pZHMiOlsiSU5URUwtU0EtMDA1ODYiLCJJTlRFTC1TQS0wMDYxNCIsIklOVEVMLVNBLTAwNjE1IiwiSU5URUwtU0EtMDA2NTciLCJJTlRFTC1TQS0wMDczMCIsIklOVEVMLVNBLTAwNzM4IiwiSU5URUwtU0EtMDA3NjciLCJJTlRFTC1TQS0wMDgyOCIsIklOVEVMLVNBLTAwODM3Il0sImF0dGVzdGVyX3R5cGUiOiJTR1giLCJ2ZXJpZmllcl9pbnN0YW5jZV9pZHMiOlsiYTI2YzIxOWItNTZkNi00NmNiLWI1OTItMjkxYjYxYjQzMTdkIiwiM2YwMzMyZTItZjJjNi00ZDlmLWI0NzMtZjA1ZDAyYzk4OWYwIiwiNDJjNTJjMWItMTcwOS00MDE2LTkwMmMtOGY3MzY3NzJkMzUxIl0sImRiZ3N0YXQiOiJkaXNhYmxlZCIsImVhdF9wcm9maWxlIjoiaHR0cHM6Ly9hbWJlci1wb2MtdXNlcjEucHJvamVjdC1hbWJlci1zbWFzLmNvbS9lYXRfcHJvZmlsZS5odG1sIiwiaW50dXNlIjoiZ2VuZXJpYyIsInZlciI6IjEuMC4wIiwiZXhwIjoxNzA0OTI2NzU0LCJqdGkiOiI3ZWQwOWIwOC1iNDEwLTRiNjAtOTNkMy1iMzA4MjRiNWU3ODAiLCJpYXQiOjE3MDQ5MjY0NTQsImlzcyI6IkludGVsIFRydXN0IEF1dGhvcml0eSIsIm5iZiI6MTcwNDkyNjQ1NH0.c9_6Mt8d9wbzs-46UVSJgIvmO_1rzYYBIYGFsGQSFphd6NjU0OTdgmsJEJ24ZG8-elOKiNH3QMn2wztHgtjpHfAWr7QNB5cV8d5eHDj9_gk68NyIFIycI9AogAeHmWOTGNTlSfuPRzuGwplnXRBQICr1kB2i-DLc01xNWJ4YhwpjuhAOT1eWXpx0nocEA3zzHD__QqKuw395Cry04ZhoCNlQDr6S7U2b4iWzvo0Vpeih64CHyFyHDo0olFZYmBjNSdObRhPtCa0vQ8T7TJbUYLUHQz8_XHFUAuHrr6alEjjb-jZFhCdjuW7ZnmdlyFkAK9MHaGal5SsRrj-VBMfsFPEqVQthieJh2IhhNB284DQ9VJsy7C7s5U1r0q0PRA-P2sB44KQ6G1YPTq7_fo7SGVQq7GSKYFZbil_Jx-YTFDPIZNHd75eVpdDyj3J84X9L6cN9EBhTJwWwZRZHh0I2x5bdABCr8Ev815o21F9ttFHKH8BtAqNm0174m2m4_AXo"
//		}
// x-sample-call-output: |
//		{
//			"wrapped_key": "DAAAABAAAAAwAAAAyKHZsencLdTeTMV1plalHIcKBDleJqk5L6mQUOpq/Xws1nes5N02g+Mt4qmq7dbDbhTYN4xZjMxuCVM3",
//			"wrapped_swk": "h9wwWK4WV/STdq4vSzrVBgATkp+MOo8NMTL+W15S+M5EcyKI8geAyUkE0Cr4ss7U22Uc7I2ETjlajNZzMjcbcEFf5h7p9i22KY5HK12ww3FC6CMTMAK2FCsy4MPyzD1luiH8W/ezssd7sDbg2VlNQlYOZ4UG/vFBJ7/c74suwa31vyj3hPelQFhkN6yFKcvoYalb1VejdCWeJ0r6/8zOJjDZrEE9XqExQtaxLFmdmYvYy3Q02vVyz0nSeP38dlx+W7ifiLR2GEPjNYmWq+N+ToDdtvb/lJOiFoRZtATFQmzBptiMsyr8mkLKzEPdB6g6ghDsW7rGSHlj5YgC2d3VbqUcUoh5ZiW65sXhrzIQ9s4ON5MFLU5ECj9/9BqThHnBtqa0tVoLfbdvmNpUB+xO994WiIoZtfAJ3JhtlPPwHShw5lAvpH0X1OSklauH8Kb8UMP3EU0FO0J29aU3glm9/9do//NHYb3mIYpZ7r5VLy31UkB68e+3hnlHDzPCbea8"
//		}
