import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const spec = JSON.parse(readFileSync(new URL("../../api/openapi.v1.json", import.meta.url), "utf8"));
assert.equal(spec.openapi, "3.1.0");
assert.equal(spec.info.version, "1.0.0");
assert.ok(spec.components.securitySchemes.BearerAuth, "bearer authentication scheme is required");
assert.ok(spec.security?.some((entry) => Object.hasOwn(entry, "BearerAuth")), "global bearer auth is required");

function resolvePointer(ref) {
  assert.ok(ref.startsWith("#/"), `Only local OpenAPI references are supported: ${ref}`);
  return ref.slice(2).split("/").map((part) => part.replace(/~1/g, "/").replace(/~0/g, "~"))
    .reduce((value, key) => {
      assert.ok(value && Object.hasOwn(value, key), `Unresolved OpenAPI reference: ${ref}`);
      return value[key];
    }, spec);
}
function parameterName(parameter) {\n  return parameter.name ?? (parameter.$ref ? resolvePointer(parameter.$ref).name : undefined);\n}\nfunction visit(value) {
  if (!value || typeof value !== "object") return;
  if (typeof value.$ref === "string") resolvePointer(value.$ref);
  for (const child of Object.values(value)) visit(child);
}
visit(spec);

const operationIds = new Set();
let operationCount = 0;
for (const [path, item] of Object.entries(spec.paths)) {
  const pathParams = new Set((item.parameters ?? []).map(parameterName).filter(Boolean));
  for (const [method, operation] of Object.entries(item)) {
    if (method === "parameters" || method.startsWith("x-")) continue;
    operationCount++;
    assert.ok(operation.operationId, `Missing operationId for ${method.toUpperCase()} ${path}`);
    assert.ok(!operationIds.has(operation.operationId), `Duplicate operationId: ${operation.operationId}`);
    operationIds.add(operation.operationId);
    assert.ok(Object.keys(operation.responses ?? {}).length > 0, `Missing responses: ${operation.operationId}`);
    if (path !== "/readyz") {
      const ownSecurity = operation.security;
      assert.ok(ownSecurity === undefined || ownSecurity.some((entry) => Object.hasOwn(entry, "BearerAuth")),
        `Unexpected auth override: ${operation.operationId}`);
      assert.ok(operation.responses["401"] && operation.responses["403"],
        `Authenticated operation must document 401 and 403: ${operation.operationId}`);
    }
    for (const name of path.matchAll(/\{([^}]+)\}/g)) {
      const parameter = name[1];
      const operationParams = (operation.parameters ?? []).map(parameterName).filter(Boolean);
      assert.ok(pathParams.has(parameter) || operationParams.includes(parameter),
        `Path parameter ${parameter} missing for ${operation.operationId}`);
    }
  }
}
assert.ok(operationCount >= 10, "Expected lifecycle, proof, claims, and readiness operations");
assert.ok(!Object.hasOwn(spec.components.schemas.CreateMigrationRequest.properties, "tenant_id"),
  "Tenant ID must not be client-selectable");
const errorCodes = spec.components.schemas.ApiError.properties.code.enum;
for (const code of ["unsupported_asset","source_unverified","migration_paused","insufficient_backing","invalid_proof"]) {
  assert.ok(errorCodes.includes(code), `Missing typed API error code: ${code}`);
}
for (const operation of ["createMigration","startVerification","submitApproval","requestActivation","cancelMigration","createDispute"]) {
  const found = Object.values(spec.paths).some((pathItem) =>
    Object.values(pathItem).some((candidate) => candidate?.operationId === operation && candidate.parameters?.some((p) => p.$ref === "#/components/parameters/IdempotencyKey"))
  );
  assert.ok(found, `Idempotency-Key required for ${operation}`);
}
console.log(`OpenAPI validation: PASS (${operationCount} operations, all local refs resolved)`);
