import test from "node:test";
import assert from "node:assert/strict";
import { authorizeTenant, ApiAuthorizationError } from "./tenant-policy.mjs";

const actor = (tenant_id, roles = ["operator"]) => ({
  sub: "user-123",
  tenant_id,
  roles,
  iss: "https://identity.example.test/",
  aud: "metorah-api",
  exp: 2_000_000_000,
});

function denied(expectedStatus, expectedCode, fn) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof ApiAuthorizationError);
    assert.equal(error.status, expectedStatus);
    assert.equal(error.code, expectedCode);
    return true;
  });
}

test("verified tenant operator can create and read resources in their own tenant", () => {
  const result = authorizeTenant({
    verifiedClaims: actor("tenant-a", ["operator"]),
    resourceTenantId: "tenant-a",
    action: "create",
  });
  assert.deepEqual(result, { subject: "user-123", tenantId: "tenant-a", action: "create" });
});

test("cross-tenant reads are concealed as not found", () => {
  denied(404, "not_found", () => authorizeTenant({
    verifiedClaims: actor("tenant-a", ["owner"]),
    resourceTenantId: "tenant-b",
    action: "read",
  }));
});

test("cross-tenant mutations are denied even to an owner", () => {
  for (const action of ["create", "verify", "approve", "activate", "cancel", "dispute"]) {
    denied(404, "not_found", () => authorizeTenant({
      verifiedClaims: actor("tenant-a", ["owner"]),
      resourceTenantId: "tenant-b",
      action,
    }));
  }
});

test("viewer cannot mutate and operator cannot activate", () => {
  denied(403, "forbidden", () => authorizeTenant({
    verifiedClaims: actor("tenant-a", ["viewer"]),
    resourceTenantId: "tenant-a",
    action: "create",
  }));
  denied(403, "forbidden", () => authorizeTenant({
    verifiedClaims: actor("tenant-a", ["operator"]),
    resourceTenantId: "tenant-a",
    action: "activate",
  }));
});

test("reviewer can approve but cannot activate", () => {
  assert.equal(authorizeTenant({
    verifiedClaims: actor("tenant-a", ["reviewer"]),
    resourceTenantId: "tenant-a",
    action: "approve",
  }).action, "approve");
  denied(403, "forbidden", () => authorizeTenant({
    verifiedClaims: actor("tenant-a", ["reviewer"]),
    resourceTenantId: "tenant-a",
    action: "activate",
  }));
});

test("missing or unverified identity claims fail closed", () => {
  denied(401, "unauthorized", () => authorizeTenant({
    verifiedClaims: { sub: "user-123", tenant_id: "tenant-a" },
    resourceTenantId: "tenant-a",
    action: "read",
  }));
  denied(401, "unauthorized", () => authorizeTenant({
    verifiedClaims: null,
    resourceTenantId: "tenant-a",
    action: "read",
  }));
});

test("unknown action fails closed", () => {
  denied(400, "invalid_request", () => authorizeTenant({
    verifiedClaims: actor("tenant-a", ["owner"]),
    resourceTenantId: "tenant-a",
    action: "admin_everything",
  }));
});
