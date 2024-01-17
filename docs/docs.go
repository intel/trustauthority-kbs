// Key Broker Service
//
// The Key Broker Service (KBS) acts as a bridge between an existing ecosystem of key management service (KMS) and a client requesting keys, by evaluating additional “key transfer policy”. This key transfer policy can enforce a client to go through attestation demonstrating it is running in a trusted execution environment (TEE) such as Intel SGX or TDX or on a trusted platform. Attestation can be provided by Intel Trust Authority (ITA). Key broker service is a relying parity (RP) as defined in IETF RATs specification.
//
// The key Broker Service (KBS) provides and retains encryption/decryption keys for various purposes. When a TEE workload requests for the decryption key to operate on a resource, the KBS requests the workloads attestation from Intel Trust Authority (ITA), verifies all digital signatures and retains the final control over whether the decryption key is issued. If the workload's attestation meets the policy requirements, the KBS issues a decryption key itself, wrapped using the public key form the workload that was attested, cryptographically ensuring that only the attested workload can decrypt the requested key.
// License: Copyright(C) 2022 Intel Corporation. All Rights Reserved.
//
//	Version:0.3.1
//	Host: kbs.com:9443
//	BasePath: /kbs/v1
//
//
//
//	SecurityDefinitions:
//	 bearerToken:
//	   type: apiKey
//	   in: header
//	   name: Authorization
//	   description: Enter your bearer token in the format <Bearer Token>
//
//swagger:meta
package kbs
