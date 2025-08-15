# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an implementation of HTTP Message Signatures per RFC 9421. The library provides functionality for signing and verifying HTTP requests and responses using various cryptographic algorithms.

## Development Commands

### Testing
- `go test` - Run all tests
- `go test ./...` - Run tests recursively for all packages
- `go test -v` - Run tests with verbose output
- `go test -run TestName` - Run specific test
- `go test -fuzz FuzzName` - Run fuzz tests (see testdata/fuzz/ for existing fuzz test data)

### Building and Linting
- `go build` - Build the package
- `go vet` - Run go vet for static analysis
- `go fmt ./...` - Format all Go files
- `go mod tidy` - Clean up module dependencies
- `go mod verify` - Verify module integrity

### Coverage
- `go test -cover` - Run tests with coverage
- `go test -coverprofile=coverage.out && go tool cover -html=coverage.out` - Generate HTML coverage report

## Architecture Overview

### Core Components

1. **Signing Pipeline** (`sign.go`, `signatures.go`)
   - `Signer` struct orchestrates request/response signing
   - `SigningProfile` defines what fields and metadata to include
   - `SigningKey` holds cryptographic material and metadata
   - Supports asymmetric (RSA, ECDSA, Ed25519) and symmetric (HMAC) algorithms

2. **Accept-Signature Support** (`accept.go`)
   - `AcceptSignature` struct for parsing Accept-Signature headers
   - `ParseAcceptSignature()` function for client-server signature negotiation
   - Support for signature profile requirements from clients

3. **Verification Pipeline** (`verify.go`)
   - `Verifier` struct handles signature verification
   - `VerifyProfile` enforces security requirements beyond basic signature validation
   - `KeyFetcher` interface for key retrieval by keyID or other metadata
   - Time-based validation for created/expires metadata with configurable tolerances

4. **Core Engine** (`base.go`)
   - `calculateSignatureBase()` generates the canonical string for signing/verification
   - `componentID` represents signature components (headers or derived values like @method, @target-uri)
   - `httpMessage` abstraction handles both requests and responses uniformly

5. **HTTP Integration** (`http.go`)
   - `NewHTTPClient()` creates signing/verifying HTTP clients
   - `NewHandler()` wraps http.Handler for automatic request verification
   - `transport` type implements http.RoundTripper for transparent signing/verification

6. **Content Integrity** (`digest.go`)
   - Automatic Content-Digest header calculation when signing
   - Support for SHA-256 and SHA-512 digests
   - Body preservation during digest calculation

### Key Utilities

- **keyman/** - In-memory key storage implementation
- **keyutil/** - PEM key file reading utilities with support for various formats
- **sigtest/** - Test helpers for signature testing

### Error Handling

The library uses a structured error system (`sigerrors.go`) with specific error types:
- `ErrNoSigMissingSignature` - Missing signature headers
- `ErrSigVerification` - Signature verification failures
- `ErrSigProfile` - Profile validation failures
- `ErrSigKeyFetch` - Key retrieval failures

### Algorithm Support

**Asymmetric:**
- RSA-PSS-SHA512 (`rsa-pss-sha512`)
- RSA v1.5 SHA256 (`rsa-v1_5-sha256`)
- ECDSA P-256 SHA256 (`ecdsa-p256-sha256`)
- ECDSA P-384 SHA384 (`ecdsa-p384-sha384`)
- Ed25519 (`ed25519`)

**Symmetric:**
- HMAC-SHA256 (`hmac-sha256`)

### Security Defaults

`DefaultVerifyProfile` provides secure defaults:
- Requires Content-Digest, @method, @target-uri fields
- Mandates 'created' and 'keyid' metadata
- 5-minute signature validity window
- Prohibits algorithm metadata (must be derived from key)
- Allows only secure algorithms (ECDSA, Ed25519, HMAC)

## Testing Approach

The codebase uses standard Go testing with:
- RFC test vectors in `testdata/` directory
- Fuzz testing for signature parsing
- Round-trip tests validating sign→verify cycles
- Comprehensive algorithm coverage

## Important Implementation Notes

- Signature base calculation follows RFC 9421 exactly
- Multi-value headers are not yet supported (will return error)
- Content-Digest is automatically calculated when included in signature fields
- Request body is preserved during signing/verification by reading and reconstructing
- Context keys are used to pass verification results through HTTP middleware
