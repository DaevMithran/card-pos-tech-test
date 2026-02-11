# Technical Challenge: Mini-HSM

## Overview
The goal of this challenge is to design and implement a **Software-based Mini HSM (Hardware Security Module)**. In a production environment, an HSM is a physical device that safeguards and manages digital keys. For this challenge, you will build a Go-based service that mimics these security properties.

You will build a **thread-safe, networked Mini HSM service** in GoLang that securely manages cryptographic keys and performs operations without ever exposing the raw private keys to the caller.

---

## Requirements

### Core Cryptographic Engine
Your service must support the following operations using the Go standard library (`crypto/*`):
* **Key Generation:** Generate ECDSA (Curve P-256) keys.
* **Sign/Verify:** Sign arbitrary data and verify signatures using stored keys.
* **Public Key Export:** Provide an endpoint to retrieve the Public Key in PEM format for a given `KeyID`.

### Key Management & Lifecycle
* **Key Identification:** Every generated key must be assigned to a unique `KeyID`.
* **Discovery:** Implement a `ListKeys` functionality that returns metadata (`KeyID`, creation timestamp, algorithm).
* **Rotation:** Implement a “Rotate” operation where a new underlying private key is generated for an existing `KeyID`.

### Persistence & Security at Rest
* **Encrypted State:** On a graceful shutdown, the HSM must save its key store to a local file.
* **Encryption at Rest:** The exported file must be encrypted using **AES-GCM**. The master encryption key should be passed to the application via an environment variable.

### Concurrency & Performance
The service must be **thread-safe**. It should handle multiple concurrent signing and generation requests without data corruption or race conditions.

### gRPC Implementation
Instead of a standard REST API, you are required to implement this service using **gRPC**. You must create your `.proto` definition. You also need to generate the Go code from this definition and implement the server logic.

---

## Constraints
* **Language:** Go (GoLang)
* **No External Databases:** Use in-memory storage with the required file-based persistence for shutdown.
* **Standard Library:** Use the Go standard library for all cryptographic operations. 3rd party packages for routing (e.g., Gin, Echo, Chi,...) or UUIDs are permitted.

---

## Evaluation Criteria
We will evaluate your submission based on:
* **Security Mindset:** Proper use of handling the sensitive data in memory.
* **Concurrency:** Correct implementation of locking mechanisms or channel-based communication.
* **Code Quality:** Idiomatic Go code, clear project structure and comprehensive error handling.
* **Resilience:** How the service handles graceful shutdowns and malformed input.

---

## Submission Instructions
1. Everything must be pushed to your **GitHub repository**.
2. Provide a **README.md** explaining how to build and run the service.