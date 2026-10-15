/**
 * Shared, non-cryptographic lifecycle *vocabulary*.
 * Not a verifier, canonical proof codec or deployed settlement SDK.
 * The initial proof encoding is separately specified in issue #25.
 */
export const MIGRATION_STATES = Object.freeze([
  'DRAFT', 'PREPARED', 'FROZEN', 'VERIFIED', 'REVIEW',
  'ACTIVATED', 'CLAIMING', 'COMPLETED', 'CANCELLED', 'DISPUTED', 'PAUSED',
]);
export const RUNTIME_VERIFICATION_IMPLEMENTED = false;
export const RELEASE_PHASE = 'DESIGN_AND_OFFLINE_VALIDATION';
