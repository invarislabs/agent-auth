/**
 * @invarislabs/agentauth: a verifier for AgentAuth in TypeScript.
 *
 * Verifies key event logs (did:agent identities), AgentSig signed requests and
 * AgentGrant delegation chains exactly as the Python reference implementation
 * does; both run the shared test vectors in ../test-vectors. Zero runtime
 * dependencies: WebCrypto (Node 20+, Deno, Bun, browsers, edge workers).
 *
 * Verification only: issuing identities and grants stays with the Python SDK
 * and CLI for now.
 */

export * from "./errors.js";
export { parseJson, canonicalJson, compareCodePoints, JsonFloat, JsonParseError, CanonicalizationError } from "./json.js";
export type { JsonObject, JsonValue, ParseOptions } from "./json.js";
export {
  b58decode, b58encode, b64uDecode, digest, isDigest, keyCommitment, multikeyToPublicKey, publicKeyToMultikey, verify,
} from "./crypto.js";
export {
  VERSION, DID_PREFIX, MAX_META_DEPTH, MAX_EVENT_DEPTH, applyEvent, eventDigest, isAgentDid, keyId, shapeOk,
  trustEmbeddedControllerKeys, verifyInception, verifyLog,
} from "./identity.js";
export type { ControllerKeyCheck, IdentityState } from "./identity.js";
export { Limits, patternCovers, patternMatches } from "./limits.js";
export {
  SCHEME, DEFAULT_MAX_SKEW, MemoryNonceCache, RequestVerifier, kidSeq, parseAuthorization, signingString,
} from "./httpsig.js";
export type { KeyResolver, ReplayCache, RequestToVerify, RequestVerifierOptions, VerifiedAgent } from "./httpsig.js";
export {
  HEADER as GRANT_HEADER, Grant, GrantChain, GrantVerifier, audienceCovers, checkCall, checkGrantBody, parseRevocation,
  scopeCovers, scopesCover, trustPrincipals, verifyRevocation,
} from "./grants.js";
export type { AuthorizedAgent, GrantVerifierOptions, RevocationCheck, RootPolicy } from "./grants.js";
export { KelPins, RegistryClient, RegistryError, registryKeyResolver, registryRevocationChecker } from "./registry.js";
export type { Fetch, RegistryClientOptions } from "./registry.js";
