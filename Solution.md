# Mini HSM

A Mini HSM service built in Go with gRPC.

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
grpcurl -plaintext -d '{}' localhost:26657 hsm.v1.Query/GetPublicKey
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
