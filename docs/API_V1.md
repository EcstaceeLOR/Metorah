# Public API v1 contract

The machine-readable contract is `api/openapi.v1.json` (OpenAPI 3.1.0). It defines readiness, migration creation/read/status, verification jobs, approvals, activation, cancellation, disputes, proof status, claim listing, and claim receipts under the `/api/v1` prefix.

## Authentication and tenant isolation

All endpoints except public `GET /readyz` require a bearer JWT. The deployed HTTP layer must verify the token's cryptographic signature, issuer, audience, expiry/not-before, subject, tenant ID, and roles before passing verified claims to `tools/api/tenant-policy.mjs`. Decoding a JWT is not verification. The policy helper intentionally accepts a value named `verifiedClaims` and must only be called after the verifier succeeds.

Tenant ID is derived from the verified token and must not be accepted from request bodies, query parameters, or client-selected headers. Every resource lookup must be scoped by both resource ID and verified tenant ID before returning data. Cross-tenant access is concealed as `404 not_found` to reduce resource enumeration. Same-tenant role failures return `403 forbidden`.

Role policy:

- `owner`, `admin`: read and all defined mutations;
- `operator`: read, create, verify, and dispute;
- `reviewer`: read, approve, and dispute;
- `viewer`: read only.

This module is an authorization policy primitive, not a deployed JWT verifier or HTTP server. The future API middleware must establish trusted claims before invoking it and must fail closed if identity, tenant, role, or resource ownership cannot be established.

## Idempotency, errors, and amount encoding

State-changing endpoints require `Idempotency-Key`; keys are scoped to tenant and operation, and a different payload with a reused key must return `idempotency_conflict`. Amounts and large block/index values are strings to avoid JavaScript integer precision loss. Cursor pagination is bounded to 100 records per page.

Error responses use a stable `error` envelope with `code`, `message`, `request_id`, and `retryable`. Codes explicitly distinguish unsupported assets, unverified sources, paused migrations, insufficient backing, invalid proofs, approval requirements, invalid transitions, and idempotency conflicts.

## Validation

CI runs `node tools/api/validate-openapi.mjs` to validate JSON/OpenAPI version, unique operation IDs, path parameters, local references, auth/error contracts, typed errors, and idempotency headers. `node --test tools/api/tenant-policy.test.mjs` tests same-tenant access, cross-tenant read/mutation denial, least-privilege roles, and missing identity claims. These are contract/policy tests; production HTTP/JWT integration tests remain required when the server is implemented.
