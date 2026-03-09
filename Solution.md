# Mini HSM

A Mini HSM service built in Go with gRPC. It manages ECDSA P-256 keys securely to perfom key generation, key rotation, sign and verify methods. As the problem statement specifies rotate keys instead of update, the solution maintains the history of all the versions. The hsm exposes http query endpoints hosting publicKey PEM via grpc-gateway.

## Features
 - [x] Key Generation
 - [x] Sign
 - [x] Verify
 - [x] Get PublicKey PEM
 - [x] Host public key PEM in an endpoint
 - [x] Encrypted Backup
 - [x] Key Rotation

## Quick Start

```bash

make proto

go mod tidy

make run
```

The gRPC Msg and Query server listens on `:26657` and the HTTP gateway hosting Query Server on `:1317`

### Usage

Create a Key Pair
```bash
grpcurl -plaintext -d '{}' localhost:26657 hsm.v1.Msg/CreateKey
```

List Key Metadata
```bash
grpcurl -plaintext -d '{}' localhost:26657 hsm.v1.Query/ListKeys
```

Get Public Key
```bash
grpcurl -plaintext -d '{ "kid": <kid> }' localhost:26657 hsm.v1.Query/GetPublicKey
```

Sign Message
```bash
grpcurl -plaintext -d '{ "kid": <kid>, "data": "aGVsbG8=" }' localhost:26657 hsm.v1.Msg/Sign
```

Verify Message
```bash
grpcurl -plaintext -d '{ "kid": "<kid>", "data": "aGVsbG8=", "signature": "<signature>"}' localhost:26657 hsm.v1.Msg/Verify
```

Rotate Key
```bash
grpcurl -plaintext -d '{ "kid": "<kid>" }' localhost:26657 hsm.v1.Msg/RotateKey
```

### Exposing Public Key via http endpoint

```curl
curl -s http://localhost:8080/hsm/v1/keys/<kid>
```

## Design Decisions

### Proto definitions separtion 

Splitting the definitions into tx, query and types with grpc Gateway HTTP annotations. This separation allows HTTP endpoints are only exposed for queries.

### Key Versioning

Key versions are maintained in an array. This differentiates the rotate operation from a standard update operation in a db. This allows signatures from any version of the kid to be verifiable if the version is specified

### Private Vault

Private keys are stored in a separate vault in a sync.Map with `kid:version` as the key. This design separates concerns of metadata and private key oeprations. The publicKey PEM is derived on creation so that privateKey is not accessed everytime. The vault is currently accessed only by the keystore.


### Concurrency

The store uses a `sync.RWMutex` that protects the keyStore state. The write locks are used in inserting or rotating a key, and read locks for query operations.

The vault uses `sync.Map` as it's an appendonly map


### Encryption

The HSM uses AES-GCM encryption as mentioned in the problem. The master key is used with the random initialization vector. The data is serialized in keystore and vault independently followed by a combined jsonMarshaling before encryption. The decryption uses the HSM key and deserializes the data to initialize the key store and vault

### Backup

The backup storage is extendable so that other storage options can be used in future. The storage module doesnt access the keystore package they are designed to be independent and modular.