export class ApiAuthorizationError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "ApiAuthorizationError";
    this.status = status;
    this.code = code;
  }
}

const READ_ROLES = new Set(["owner", "admin", "operator", "reviewer", "viewer"]);
const ACTION_ROLES = Object.freeze({
  read: READ_ROLES,
  create: new Set(["owner", "admin", "operator"]),
  verify: new Set(["owner", "admin", "operator"]),
  approve: new Set(["owner", "admin", "reviewer"]),
  activate: new Set(["owner", "admin"]),
  cancel: new Set(["owner", "admin"]),
  dispute: new Set(["owner", "admin", "operator", "reviewer"]),
});

/**
 * Enforce tenant and role scope after the HTTP layer has cryptographically verified the JWT.
 * Do not pass decoded-but-unverified token payloads to this function.
 * Tenant scope is taken only from verifiedClaims.tenant_id, never from client input.
 */
export function authorizeTenant({ verifiedClaims, resourceTenantId, action }) {
  if (
    !verifiedClaims ||
    typeof verifiedClaims.sub !== "string" ||
    typeof verifiedClaims.tenant_id !== "string" ||
    !Array.isArray(verifiedClaims.roles)
  ) {
    throw new ApiAuthorizationError(401, "unauthorized", "A verified tenant-scoped identity is required.");
  }

  if (typeof resourceTenantId !== "string" || resourceTenantId.length === 0) {
    throw new ApiAuthorizationError(404, "not_found", "Resource not found.");
  }

  if (verifiedClaims.tenant_id !== resourceTenantId) {
    // Deliberately return the same code as a missing resource to avoid cross-tenant enumeration.
    throw new ApiAuthorizationError(404, "not_found", "Resource not found.");
  }

  const allowed = ACTION_ROLES[action];
  if (!allowed) {
    throw new ApiAuthorizationError(400, "invalid_request", "Unsupported authorization action.");
  }

  if (!verifiedClaims.roles.some((role) => allowed.has(role))) {
    throw new ApiAuthorizationError(403, "forbidden", "Role is not permitted to perform this action.");
  }

  return Object.freeze({
    subject: verifiedClaims.sub,
    tenantId: verifiedClaims.tenant_id,
    action,
  });
}
