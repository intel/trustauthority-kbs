# Key Broker Service - Intel® Trust Authority

The Intel Trust Authority Key Broker Service (KBS) is deployed as a container image. The Key Broker Service (KBS) enables key distribution using a Trusted Execution Environment (TEE) like SGX and TDX attestation to authorize key transfers by retaining image decryption keys. The KBS acts as a bridge between an attestation service (like Intel Trust Authority) and the existing ecosystem of KMIP key management platforms. It brokers access to the secrets stored in the key management services by evaluating attestation tokens against a key transfer policy that informs the broker of the specific trust requirements for retrieving a key.

The KBS provides and retains encryption/decryption keys for various purposes. When a TEE workload requests the decryption key to operate on a resource, the KBS requests the workload's attestation from Intel Trust Authority, verifies all digital signatures, and retains the final control over whether the decryption key is issued. If the workload's attestation meets the policy requirements, the KBS issues a decryption key, wrapped using the public key from the attested workload, cryptographically ensuring that only the attested workload can decrypt the requested key. The KBS also acts as a policy broker that analyzes key requests, decides how to respond, and wraps the keys using a bound public key. The key broker Service connects to a backend Hashicorp Vault KMS and third-party KMIP-compliant key management servers like PyKMIP for key creation and vaulting services.

# About the KBS

In remote attestation, a relying party (a key manager, secrets vault, network access controller, etc.) must establish trust with a workload (an attester). It relies on a remote attestation service (a verifier) to appraise evidence from the attester and issue an attestation of that appraisal (an attestation token).

However, there is a gap between relying parties and verifiers - for example, Vault does not natively integrate with any remote attestation authority. The KBS attempts to fill this gap by providing an intermediary such as Hashicorp Vault or PyKMIP KMS.

A KBS in the backend can plug into a Key Management Interoperability Protocol (KMIP) Key Management Service (KMS), i.e., the KBS connects to a backend 3rd Party KMIP-compliant KMS for key creation and vaulting services such as Harshicorp Vault or PyKMIP.

## KBS use cases

The KBS is a relying party in a remote attestation architecture. It provides the following functionalities:

- Manages the policies associated with a key
- Provides the interface to support key request/transfer in two situations:
	- Background check mode - The key is requested/released without an attestation token from ITA in the request body. Instead, the KBS requires a TEE quote, verifier-nonce, and runtime data, i.e., the public key created by the workload that was attested
	- Passport mode - A POST request to the Key request URL with an attestation token in the request body

### Passport verification mode

In Passport Verification mode, a relying party (a TEE agent or the KBS client) makes an attestation request directly to the verifier (Trust Authority Attestation Service) and gets an attestation token. The token is used to call the KBS key transfer API to request a key.

The KBS verifies the legitimacy of the attestation token, and whether it complies with the key policy associated with the key ID. If it does, the requested key is issued.

### Background verification mode

The workload (key requester) makes a request to the KBS to retrieve a particular key. The KBS then reaches out to Intel Trust Authority to get the nonce which is forwarded to the workload to get a quote. The quote is then sent to Intel Trust Authority along with the nonce to get the attestation token.

**Background verification mode steps**

- KBS checks the corresponding key policy to see what type of attestation is required.
- If the attestation type and attestation token are not provided as a part of the key transfer API request, KBS requests a verifier nonce from Intel Trust Authority.
- Intel Trust Authority responds with a nonce. KBS responds to the key requestor with the same nonce and attestation type present in the key policy.
- The key requestor retrieves the quote from the DCAP Quote Generation Library and sends a request to the KBS, this time with a Quote, runtime-data (public-key generated inside TEE) in the request body, along with a verifier-nonce and attestation-type.
- KBS checks if the attestation type in the request is the same as the attestation type in the key policy.
- If the attestation type matches with the key policy, KBS forwards the request to Intel Trust Authority with the Quote, Runtime-data, and a verifier-nonce; it also optionally sends a list of policy IDs to be matched by Intel Trust Authority in the request body.
- Intel Trust Authority verifies the nonce and Quote and then issues the attestation token to KBS on successful verification.
- KBS then parses the attestation token to get all the claims and matches the token claims with the policy associated with the key to be retrieved.
- If all the token claims match against the policy, KBS creates an SWK and wraps the secret/key Key with SWK, and SWK is wrapped with a public key received in the request (runtime-data).
- KBS responds with both wrapped requested key and wrapped SWK to the key requestor.

## Key Broker System Installation

Installing the Intel Key Broker System requires a Key Management System to be installed first. The process is as follows:

- Install a Key Management System 
- Build the Key Broker System 
- Install the KBS
- KBS key creation and key retrieval

### Prerequisites

- You must have an Intel Trust Authority account set up with access to the Trust Authority Download center
- Hashicorp Vault KMS or PyKMIP must be installed and running

### Install the Key Management System (KMS)

Intel's KBS works with two Key Management Systems, [Hashicorp Vault](#install-hashicorp-vault-kms) OR [PyKMIP](#install-pykmip). Follow the installation instructions for the KMS appropriate for your environment:

#### Install Hashicorp vault KMS

Follow these instructions to install the Hashicorp vault KMS. If your organization is using the PyKMIP KMS, follow the instructions found [here](#install-pykmip).

1. Install Vault according to the instructions provided here: https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install.

2. Create a Vault server config file: https://developer.hashicorp.com/vault/docs/configuration.

3. Start Vault server: https://developer.hashicorp.com/vault/docs/commands/server.

4. Initialize the vault server: https://developer.hashicorp.com/vault/docs/commands/server. Securely store/save the keys.

5. Unseal the Vault server: https://developer.hashicorp.com/vault/docs/commands/operator/unseal.

6. Login to the vault by running the following command:

   ```bash
   vault login <root-token>
   ```

7. Enable a kv secrets engine for KBS to use.

    ```bash
   vault secrets enable -path=keybroker kv
    ```

8. In the KBS config file, add the following Vault server information:

    ```bash
    VAULT_SERVER_IP=<vault server IP address>
    VAULT_SERVER_PORT=<vault port number; default 8200>
    VAULT_CLIENT_TOKEN=<vault root token>
    ```

#### Install PyKMIP

Follow these instructions to install the PyKMIP KMS. If your organization is using the Hashicorp vault KMS, follow the instructions found [here](#install-hashicorp-vault-kms).

> [!Note]
> The user must create all the certificates/keys required for KBS-PyKMIP communication. The KBS only reads the configuration file provided by the user and, therefore, uses the communication type defined by the user in that file. 

1. Follow the instructions at https://pykmip.readthedocs.io/en/latest/installation.html to install PyKMIP.

2. Create server certificates and configure the server as provided in the instructions here: https://pykmip.readthedocs.io/en/latest/server.html.

3. In the KBS config file, add the following PyKMIP server information:

    ```bash
    KMIP_CLIENT_KEY_PATH=<path to KMIP client key>
    KMIP_ROOT_CERT_PATH=<path to KMIP root certificate>
    KMIP_CLIENT_CERT_PATH=<path to KMIP client certificate>
    KMIP_SERVER_IP=<KMIP server IP address>
    KMIP_SERVER_PORT=<KMIP server port number>
    KMIP_HOSTNAME=hostname where KMIP is running
    KMIP_USERNAME=KMIP server username
    KMIP_PASSWORD=KMIP password
    KMIP_VERSION=KMIP version
    ```

### Build the KBS

KBS can be built using targets from Makefile.

`make docker` is used to build the KBS docker image (key-broker-service:v1.0.0) using the Dockerfile.

### Install the KBS

On Linux, follow the steps below to install the KBS:

1. Create directories.

   Create the following directories on the host machine.
   
   ```bash
   mkdir -p /opt/kbs/users
   mkdir /opt/kbs/keys
   mkdir /opt/kbs/keys-transfer-policy
   mkdir -p /etc/kbs/certs/tls
   mkdir /etc/kbs/certs/signing-keys
   ```
   
> [!Note]
> > The user data and keys are not encrypted, so they must be stored in a protected filesystem.

2. Configure the KBS.

   Create a kbs.env file with all the configuration variables listed below.

   ```bash
   LOG_LEVEL=<DEBUG, INFO, TRACE, ERROR>
   KEY_MANAGER=<VAULT or KMIP, default VAULT>
   ADMIN_USERNAME=<kbs admin username>
   ADMIN_PASSWORD=<kbs admin password>
   HTTP_READ_HEADER_TIMEOUT=<kbs server read header timeout, default 10sec>
   BEARER_TOKEN_VALIDITY_IN_MINUTES=<kbs auth token validity, default 5 min>
   TRUSTAUTHORITY_API_URL=<Intel Trust Authority API url>
   TRUSTAUTHORITY_API_KEY=<Intel Trust Authority API key>
   TRUSTAUTHORITY_BASE_URL=<Intel Trust Authority portal base URL>
   AUTHENTICATION_DEFEND_MAX_ATTEMPTS=<max number of invalid login attempts;default 5 attempts>
   AUTHENTICATION_DEFEND_INTERVAL_MINUTES=<time interval of number of invalid token fetch attempts made;default 1 min>
   AUTHENTICATION_DEFEND_LOCKOUT_MINUTES=<number of minutes the user is blocked from getting a token in case of exceeds the number of attempts;default 1 min>
   SAN_LIST=<SAN list for KBS tls certificate>
   Intel Trust Authority works with two Key Management Services, the free version of Hashicorp vault KMS and PyKMIP. Select the appropriate configuration for your environment and add it to the env file.
   ```

   ***Hashicorp vault KMS configuration***

   Only use these configurations if the KBS if using Hashicorp's free version.

   ```bash
   VAULT_SERVER_IP=<vault server IP address>
   VAULT_SERVER_PORT=<vault port number; default 8200>
   VAULT_CLIENT_TOKEN=<vault root token>
   ```

   ***PyKMIP configuration***

   Only use these configurations if using PyKMIP KMS.

   ```bash
   KMIP_CLIENT_KEY_PATH=<path to KMIP client key>
   KMIP_ROOT_CERT_PATH=<path to KMIP root certificate>
   KMIP_CLIENT_CERT_PATH=<path to KMIP client certificate>
   KMIP_SERVER_IP=<KMIP server IP address>
   KMIP_SERVER_PORT=<KMIP server port number>
   KMIP_HOSTNAME=hostname where KMIP is running
   KMIP_USERNAME=KMIP server username
   KMIP_PASSWORD=KMIP password
   KMIP_VERSION=KMIP version    
   ```
3. Optionally, configure a proxy setting.

    If you're running behind a proxy, use this configuration.

    ```bash
    http_proxy=<http proxy>
    https_proxy=<https proxy>
    ```
4. Run the KBS container.

    ```bash
    docker run -d --restart unless-stopped --name kbs --env-file <KBS env file> -p <KBS port>:9443 -v /etc/kbs/certs:/etc/kbs/certs -v /etc/hosts:/etc/hosts -v /opt/kbs:/opt/kbs trustauthority/key-broker-service:v1.0.0
    ```
## KBS key creation and key retrieval

Once the KBS service is installed and running successfully, follow the steps below to create keys and retrieve them. The KBS system admin user must use the admin credentials provided during KBS installation to retrieve the “admin” user token. The "admin" user is created when the KBS container is started based on KBS config ADMIN_USERNAME and ADMIN_PASSWORD. This user token has admin privileges to KBS, i.e., access to all KBS REST APIs.

### Fetch the bearer token

#### POST /token

Creates a JWT for the user specified in the request.

Use the "admin" token to create key transfer policies by defining the rules to retrieve the keys from the backend KMS (KMIP).

***Example request body***

```bash
{
  "password": "testPassword",
  "username": "testUser"
}
```

### Create a key transfer policy for the SGX or TDX workload

A key transfer policy contains the information required for a key to be released to a relying party. 

A user with the "key-transfer-policy:create" permission in the token can create a policy for a key.

#### POST /key-transfer-policies 

Creates a key transfer policy. Only one SGX or TDX key transfer policy can be created at a time. A key transfer policy can be created in the following ways:

- by providing only a list of policy-ids 
- by providing only TDX or SGX attributes 
- by providing both a list of policy-ids and TDX or SGX attributes

***Example SGX policy***

```bash
	{
    "attestation_type": "SGX",
    "sgx":{
            "attributes":{
                "mrsigner": ["83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e"],
                "isvprodid":[0],
                "mrenclave":["83f4e819861adef6ffb2a4865efea9337b91ed30fa33491b17f0d5d9e8204410"],
                "isvsvn":0,
                "enforce_tcb_upto_date":false
            }
		}
	}
```

***Example TDX policy***

```bash
	{
    "attestation_type":["TDX"],
    "tdx":{
            "attributes":{
                "mrseam":["2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656"],
                "mrsignerseam":["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"],
                "seamsvn":"3",
                "mrtd":["5f53c3881242a5b418854923bb4adec34c72aa4b570d526179d63f9ee6e4cefb6abd4f0f35e5e6e29655a60d90bcf27f"],
                "rtmr0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "rtmr1": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "rtmr2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "rtmr3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "enforce_tcb_upto_date" : "false"
            }
		}
	}
```

### Create a key

Use the Keys API to create new keys and provide the key-transfer-policy ID in the POST request.

#### POST /keys

Creates or Registers a key.

***Request body for key creation***

```bash
{"key_information":
{
"algorithm": "RSA",
"key_length": 3072
},
"transfer_policy_id" : "0855be44-45bd-4ff3-b545-7987e6a1c36b"
}
```

### Retrieve the key 

####  POST /keys/{id}/transfer

Please refer to [Passport verification mode](#passport-verification-mode) and [Background verification mode](#background-verification-mode) documentation on how the key is released.

***Sample request for passport mode***

```bash
{
"attestation_token": token
}
```

***Sample request for background mode***

```bash
{
"quote": "{{SGX-QUOTE}}",
"nonce": {
"val": "{{NONCE}}",
"iat": "{{NONCE-DATE}}",
"signature": "{{NONCE-SIGNATURE}}"
},
"user_data": "{{USER-DATA}}"
}
```

#### Retrieve the key without TEE attestation

Keys can be retrieved from KBS without requiring TEE attestation and TEE evidence verification. The keys released from KBS are always wrapped. Providing only a public key (must be an RSA 2048 bits key) to wrap the secret is one way to retrieve the key from KBS. Please refer to the following API to retrieve the key without Intel Trust Authority.

URL: POST /kbs/v1/keys/{id}

***Sample request***

```bash
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjtGIk8SxD+OEiBpP2/T
JUAF0upwuKGMk6wH8Rwov88VvzJrVm2NCticTk5FUg+UG5r8JArrV4tJPRHQyvqK
wF4NiksuvOjv3HyIf4oaOhZjT8hDne1Bfv+cFqZJ61Gk0MjANh/T5q9vxER/7TdU
NHKpoRV+NVlKN5bEU/NQ5FQjVXicfswxh6Y6fl2PIFqT2CfjD+FkBPU1iT9qyJYH
A38IRvwNtcitFgCeZwdGPoxiPPh1WHY8VxpUVBv/2JsUtrB/rAIbGqZoxAIWvijJ
Pe9o1TY3VlOzk9ASZ1AeatvOir+iDVJ5OpKmLnzc46QgGPUsjIyo6Sje9dxpGtoG
QQIDAQAB
```

Please Refer to the API docs for more information.

## Format of the released key

KBS creates a secret wrapping key (SWK) to wrap keys/secrets released from it. The SWK is a symmetric key. The KMS is wrapped using the SWK, and the SWK is wrapped as an asymmetric key pair where the public key is retrieved from the attestation token from Intel Trust Authority (the workload creates a key pair and adds it to the "tee-held-data" claim in the token).

Sample output of key retrieval keys/{id}/transfer is as follows:

```bash
{
"wrapped_key" : ,
"wrapped_swk": <wrapped AES key with the public key from user/workload>
}
```

- wrapped key - The key from KMS is retrieved and wrapped with the AES-GCM wrapping algorithm using the SWK key.
- wrapped SWK - The symmetric SWK key is wrapped using the RSA-OAEP algorithm using the public key provided in the Intel Trust Authority attestation token from the "tee-held-data" claim. The asymmetric key pair is usually created by the workload and sent to  Intel Trust Authority along with the quote when the attestation token is retrieved.
- 
The intent of wrapping the keys before releasing them is to protect the keys in transit, and also, the keys are meant to be decrypted only by the entity requesting them.

## Managing users

An Admin user is created using the credentials entered when the container is started. The credentials provided when the container is started are assigned to the admin. The admin user has access to all the KBS APIs and, therefore, can create other users.  

#### Create users

The admin user leverages the `POST /users` API to create other KBS users.

#### POST /users

```bash
{
  "password": "testPassword",
  "permissions": [
    "users:create",
    "users:search"
  ],
  "username": "testUser"
}
```

> [!Note]
> Please use the [openapi.yml](docs/openapi.yml)swagger docs to refer to each of the APIs mentioned above to create a token, keys, etc.
