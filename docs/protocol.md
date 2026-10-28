# Protocol specification (v0.4)

This document describes AgentAuth's wire formats and verification rules precisely enough to write a compatible client or verifier in another language. The Python package is the reference implementation. If this document and the code disagree, the code wins, and the disagreement should be fixed here. The shared [test vectors](../test-vectors/README.md) turn these rules into concrete cases. Any implementation, including the [TypeScript verifier](../ts/README.md), must pass them.

**Compatibility.** The wire formats and version strings are unchanged since v0.3 (`agentauth/1`, `agentauth-request/1`, `agentauth-grant/1`, `agentauth-revocation/1`), and everything a v0.3 client produces is still accepted. v0.4 makes **verification stricter**: inputs that v0.3 accepted only by accident (duplicate header parameters, unknown fields, non-canonical encodings, out-of-range numbers) are now rejected. The October 2026 security review tightened a few more rules: canonical grant payloads, ASCII-only audiences and scopes, no stateful limits on audience `"*"`, and controller key binding. [§9](#9-changes-in-v04) lists every change.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

- [1. Primitives](#1-primitives)
- [2. Identifiers and key event logs](#2-identifiers-and-key-event-logs)
- [3. Request authentication (`AgentSig`)](#3-request-authentication-agentsig)
- [4. Capability grants (`AgentGrant`)](#4-capability-grants-agentgrant)
- [5. Limits](#5-limits)
- [6. Revocation](#6-revocation)
- [7. Registry HTTP API](#7-registry-http-api)
- [8. Version strings and constants](#8-version-strings-and-constants)
- [9. Changes in v0.4](#9-changes-in-v04)

---

## 1. Primitives

### 1.1 Signatures

- **Algorithm:** Ed25519 (RFC 8032).
- **Encoding:** the 64-byte signature, base64url **without padding** (`b64u`).
- **Strict decoding.** Verifiers MUST reject any base64url string that is not the canonical unpadded encoding of its bytes: padding (`=`), characters outside `A–Z a–z 0–9 - _`, a length ≡ 1 (mod 4), or non-zero unused trailing bits. (Many base64 libraries silently skip stray characters, which would let one signature have several spellings.)

### 1.2 Public keys (multikey)

A public key is encoded as a multibase base58btc string of the multicodec `ed25519-pub` prefix (`0xed 0x01`) followed by the 32 raw key bytes:

```
multikey = "z" + base58btc(0xED 0x01 || pubkey[32])      → starts with "z6Mk"
```

This is the same encoding `did:key` uses.

### 1.3 Digests

A digest is a self-describing SHA-256 multihash, multibase-encoded:

```
digest(x) = "z" + base58btc(0x12 0x20 || SHA-256(x))
```

### 1.4 Canonical JSON

Everything that gets signed or hashed is serialized as canonical JSON:

- object keys sorted lexicographically (by code point);
- no insignificant whitespace (separators `,` and `:`);
- UTF-8, with non-ASCII characters emitted as-is (not `\u` escaped);
- **floating-point numbers MUST NOT appear**. Only strings, integers, booleans, `null`, arrays and objects are allowed.
- strings MUST be valid Unicode (no lone surrogates).
- when parsing JSON that will be verified, implementations SHOULD reject duplicate object keys, `NaN` and `Infinity` (the reference registry does). For grant payloads this is a MUST (§4.2).
- implementations MUST keep each number's lexical type when parsing: `1.0` is a float (and so rejected), not the integer 1, and an integer beyond ±(2⁵³−1) must not be silently rounded. JavaScript's `JSON.parse` does both, so it can't be used on data that gets verified.

For the payloads AgentAuth signs (ASCII object keys, integers within ±2⁵³), this produces the same bytes as RFC 8785 (JCS). Implementations SHOULD NOT rely on equivalence outside that range: JCS sorts keys by UTF-16 code units and treats all numbers as IEEE doubles.

### 1.5 Base58btc alphabet

`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`. Leading zero bytes are encoded as leading `1`s.

---

## 2. Identifiers and key event logs

### 2.1 Events

An identity is an ordered list of **events**. Each event is an envelope:

```json
{
  "body":   { ... },
  "signer": "did:agent:…",
  "sig":    "<b64u Ed25519 signature over canonical_json(body)>",
  "controller_proof": { "key": "<multikey>", "sig": "<b64u>" }
}
```

`controller_proof` appears only on inception events that name a controller, and MUST NOT appear anywhere else. An envelope with any other top-level field is invalid.

The **event digest** is `digest(canonical_json(body))`.

### 2.2 Inception

```json
{
  "v": "agentauth/1",
  "type": "inception",
  "seq": 0,
  "prev": null,
  "key": "<current multikey>",
  "next": "<commitment to next key>",
  "controller": null | "did:agent:…",
  "meta": { },
  "ts": "2026-09-26T09:30:00Z",
  "did": "did:agent:…"
}
```

- **Key commitment:** `commitment(k) = digest(utf8(k))`, where `k` is the next key's multikey *string*.
- **DID derivation:** take the body **without** the `did` field, compute `d = digest(canonical_json(body_without_did))`, and drop the leading `z`:

  ```
  did = "did:agent:" + d[1:]            → e.g. did:agent:QmfJZ…
  ```

A verifier MUST check that:

1. `v == "agentauth/1"`, `type == "inception"`, `seq == 0` (an integer, not a boolean), `prev == null`, and `ts` matches `YYYY-MM-DDThh:mm:ssZ`.
2. The body has **exactly** the fields shown above (no more, no fewer).
3. `key` is a valid Ed25519 multikey, and `next` is a well-formed digest (§1.3: `z` + base58btc of the 34-byte sha2-256 multihash), and `next != commitment(key)`. Pre-rotation is mandatory, and committing to the current key would make it meaningless.
4. `did` equals the derivation above.
5. `signer == did`, and `sig` verifies against `key`.
6. `controller` is `null`, or an agent DID different from `did`.
7. `meta` is an object nested at most 16 levels deep.
8. If `controller` is set: `controller_proof` is an object with exactly `key` and `sig`, and `controller_proof.sig` MUST verify over `canonical_json(body)` with `controller_proof.key`. A registry MUST additionally check that `controller_proof.key` is the controller's **current** key, and MUST make that check atomically with storing the event (no rotation of the controller may slip in between).
9. Before anything else, the whole event (envelope included) is nested at most **24** levels deep and holds no integer outside ±(2⁵³−1). Verifiers check this iteratively, before canonicalizing or hashing, so deep nesting is rejected rather than exhausting a stack.

**Controller key binding.** A signature check alone only proves that *some* key signed a controller proof or a controller deactivation. Clients that replay a log they fetched (rather than a registry checking live state) MUST also check that the key appears in the controller's own verified key event log (any key it has held). Otherwise a registry, or anyone serving logs, could append a "controller deactivation" signed by a key the controller never had. The reference SDK does this in `RegistryClient.verified_state`, `RegistryKeyResolver` and `RegistryPool` (`bound_controller_check`).

A DID is `did:agent:` followed by 40–60 base58btc characters (in practice 46). Verifiers SHOULD reject anything else wherever a DID is expected.

### 2.3 Rotation

```json
{
  "v": "agentauth/1", "type": "rotation", "did": "…", "seq": n, "prev": "<digest of event n-1>",
  "key": "<newly revealed multikey>", "next": "<commitment to the following key>", "ts": "…"
}
```

On top of the common checks (§2.5), a verifier MUST check that:

- `signer == did`;
- `commitment(key) == state.next`, meaning the revealed key matches the previous commitment;
- `next` is a well-formed digest, and `next != commitment(key)`;
- `sig` verifies against the **new** `key`.

### 2.4 Deactivation

```json
{
  "v": "agentauth/1", "type": "deactivation", "did": "…", "seq": n, "prev": "…",
  "key": "<signing multikey>", "next": null, "ts": "…"
}
```

A deactivation is valid if either of these holds:

- **Self-deactivation:** `signer == did`, and `commitment(key) == state.next` (signed with the pre-committed recovery key); or
- **Controller deactivation:** `signer == state.controller`, and `key` is the controller's current key. A registry checks this against live state, atomically with storing the event. A client replaying a log MUST check that `key` is in the controller's verified key history (see *controller key binding* in §2.2).

In both cases `sig` MUST verify against `key` and `next` MUST be `null`. After deactivation the identity has no key, and no further events are accepted.

### 2.5 Checks common to every non-inception event

- The body has exactly the fields `v, type, did, seq, prev, key, next, ts`; `type` is `rotation` or `deactivation`; `ts` has the format in §2.2; there is no `controller_proof`.
- The identity MUST be active.
- `body.did` MUST equal the identity's DID.
- `seq` MUST be exactly `state.seq + 1`.
- `prev` MUST equal the digest of the previous event.

### 2.6 Derived state and key IDs

Replaying the log gives the identity's state: `{did, seq, key, next, controller, meta, active, created, updated, last_digest, key_seq}`. The **key ID** of the current key is:

```
kid = did + "#key-" + key_seq          (key_seq = seq of the event that established the key)
```

### 2.7 DID document

The registry serves a W3C DID resolution result:

```json
{
  "didDocument": {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    "id": "did:agent:…",
    "controller": ["did:agent:…", "<controller DID, if any>"],
    "verificationMethod": [{ "id": "<kid>", "type": "Multikey", "controller": "<did>", "publicKeyMultibase": "<key>" }],
    "authentication": ["<kid>"],
    "assertionMethod": ["<kid>"],
    "agent": { "...meta..." }
  },
  "didDocumentMetadata": {
    "created": "…", "updated": "…", "deactivated": false, "versionId": "<seq>", "nextKeyCommitment": "…"
  }
}
```

A deactivated identity has empty `verificationMethod`, `authentication` and `assertionMethod` lists.

---

## 3. Request authentication (`AgentSig`)

### 3.1 Header

```
Authorization: AgentSig did="<did>",kid="<kid>",aud="<host[:port]>",ts="<unix seconds>",nonce="<random>",sig="<b64u>"
```

Parameter values MUST NOT contain `"`. Parameters are separated by `,` (optional whitespace around it). The header MUST NOT be longer than 4096 bytes.

- `did` is a `did:agent:` identifier (§2.2).
- `kid` is `did + "#key-" + n` for that same `did`, with `n` a decimal integer without leading zeros.
- `ts` is a decimal integer of 1–15 ASCII digits (no sign, spaces, `_` or decimal point).
- `nonce` is 16–128 characters from `A–Z a–z 0–9 - _ . ~ + / =`. It SHOULD have at least 128 bits of entropy (the reference client uses 16 random bytes, base64url-encoded: 22 characters).
- `aud` is 1–255 printable ASCII characters (`0x21`–`0x7E`) other than `,` and `"`. It's compared with the verifier's audiences ASCII-case-insensitively.

### 3.2 Signing string

```
agentauth-request/1 \n
<METHOD, upper-case> \n
<aud, lower-case> \n
<path, plus "?" + raw query if any> \n
<ts> \n
<nonce> \n
<digest(request body bytes)> \n
<digest(value of the AgentGrant header, or "" if absent)>
```

The lines are joined with `\n`, with no trailing newline, and encoded as UTF-8. `aud` is the `host[:port]` the client is sending to, as written in the URL's authority. An empty body is hashed as the empty byte string.

### 3.3 Verification

A verifier configured with a set of accepted audiences MUST, in this order:

1. Parse the header. All six parameters are required; a parameter that appears twice, or text that isn't a `name="value"` list, makes the header invalid.
2. Reject if `aud` (lower-cased) is not one of its audiences. A verifier that serves several audiences from one application and routes by `Host` SHOULD also require `aud` to equal the request's `Host` (reference: `bind_host=True`).
3. Reject if `ts` is malformed or `|now − ts| > max_skew`. The default is 120 s.
4. Reject if `nonce`, `did` or `kid` is malformed (§3.1).
5. Resolve `did` to its current `(key, kid)`. Reject if unknown or deactivated. If the presented `kid` has a **higher** key sequence than the cached one, the verifier SHOULD refresh its cache once before rejecting, and SHOULD rate-limit such forced refreshes per DID (the reference resolver allows one per second).
6. Reject if the presented `kid` isn't the current `kid`.
7. Verify `sig` over the signing string, using the verifier's own view of method, path, body and `AgentGrant` header. The path is the **raw request target** as received (percent-encoding intact), not a decoded form.
8. Reject if `(did, nonce)` has been seen within the replay window (at least 2 × `max_skew` + 1 s; the reference verifier refuses a replay cache configured with a shorter TTL). Record the nonce **only after** the signature verifies. The replay cache MUST be shared by every process that accepts requests for the same audience.

If the verifier cannot complete a step because a dependency failed (key resolution, replay cache), it MUST reject the request; the reference implementation answers 503 so clients can tell an outage from an authentication failure.

---

## 4. Capability grants (`AgentGrant`)

### 4.1 Grant body

```json
{
  "v": "agentauth-grant/1",
  "id": "<random, ≥128 bits, b64u>",
  "iss": "<issuer DID>",
  "kid": "<issuer's kid at issue time>",
  "sub": "<subject DID>",
  "scope": ["tools.search"],
  "aud": ["tools.example.com"],
  "nbf": 1790431690,
  "exp": 1790432590,
  "depth": 0,
  "parent": null | "<parent grant id>",
  "limits": { }
}
```

- `scope` and `aud` are sorted (by code point) and de-duplicated, and `aud` is lower-cased (ASCII). Verifiers MUST reject a body where this doesn't hold, so one grant has exactly one form.
- A grant with stateful limits (`spend.total`, `rate` or `uses`, §5.4) MUST NOT have the audience `"*"`. Every service keeps its own counters, so a budget on `"*"` would be granted once per service. Issuers refuse it (400) and verifiers reject it (403).
- `limits` is omitted when there are no limits (see §5).
- A body with any field not shown above is **invalid** (fail closed: a future constraint must never be silently ignored).
- `id` and `parent` are 1–128 characters from `A–Z a–z 0–9 _ - . :`. `iss` and `sub` are agent DIDs; `kid` starts with `iss + "#key-"`. `scope` has 1–64 entries, `aud` 1–32 entries of 1–255 printable ASCII characters (`0x21`–`0x7E`) other than `,` and `"`. `nbf` and `exp` are integers in [0, 2⁵³−1]; `depth` is a non-negative integer.

### 4.2 Encoding

```
grant  = b64u(canonical_json(body)) + "." + b64u(signature over canonical_json(body))
header = grant_root "," grant_1 "," … "," grant_leaf          (at most 8 links)
```

The header name is `AgentGrant`. Verifiers MAY reject headers longer than 32 KiB (the reference implementation does).

The payload MUST be exactly `canonical_json(body)`, byte for byte. Verifiers decode it, reject duplicate object keys, floats, integers outside ±(2⁵³−1) and nesting deeper than 8 levels (400), re-canonicalize the result and reject it (400) unless it equals the bytes received. Without this, two JSON parsers (say, Python's and JavaScript's) could read different values out of the same signed token: a duplicate `sub` key, or `1.0` versus `1`.

### 4.3 Scopes

- A scope is 1–128 printable ASCII characters (`0x21`–`0x7E`).
- `*` may only appear as the whole scope (`"*"`) or as a trailing `.*` (`"tools.*"`).
- `covers(p, c)` holds when `p == "*"`, or `p == c`, or `p` ends in `.*` and `c` starts with `p` minus the `*` and `c != that prefix`. So `tools.*` covers `tools.search` and `tools.*`, but not `tools`.
- A set of scopes P covers a set C if every `c` in C is covered by some `p` in P.

### 4.4 Audiences

A set of audiences P covers C if `"*"` is in P, or every element of C is in P (compared ASCII-case-insensitively; audiences are ASCII-only, so no Unicode case folding is involved).

### 4.5 Verification

Given the `AgentGrant` header, the authenticated requester DID `R`, and the request audience `A`, a verifier MUST:

For each link `g[i]`, root first:

1. Check `v` and the field rules in §4.1 (types, formats, no unknown fields). Integers are never booleans.
2. Check that every scope is valid (§4.3), `iss != sub`, and that the same `(iss, id)` doesn't appear twice in the chain.
3. Check `nbf − 60 ≤ now < exp + 60`, and `0 < exp − nbf ≤ 86400`.
4. Check that `aud` covers `A`.
5. Parse `limits` (§5). Unknown limit fields make the grant invalid.
6. If `i == 0`: `parent` MUST be `null`.
   Otherwise, with `p = g[i−1]`:
   - `g.parent == p.id` and `g.iss == p.sub`;
   - `p.depth ≥ 1` and `g.depth ≤ p.depth − 1`;
   - `p.scope` covers `g.scope`, and `p.aud` covers `g.aud`;
   - `g.nbf ≥ p.nbf` and `g.exp ≤ p.exp`;
   - `p.limits` is only narrowed by `g.limits` (§5.2).
7. Resolve `g.iss` to its current `(key, kid)`. Reject if the issuer is unknown or deactivated, or if `g.kid` isn't the issuer's **current** kid (the grant must be re-issued after the issuer rotates). Then verify the signature.

Then:

8. The leaf's `sub` MUST equal `R`.
9. Apply the service's **root policy** to `(root.iss, A)`. It returns the scopes that principal may authorize at this service, or nothing if the principal isn't trusted. Reject if nothing is returned, or if the returned scopes don't cover `root.scope`.
10. Reject if any `(g.iss, g.id)` in the chain has been revoked (§6).

Any failure of a dependency in steps 7, 9 or 10 (registry, policy store, revocation service) MUST cause rejection (reference: 503).

The effective scopes are the **leaf's** scopes. The endpoint's required scopes MUST be covered by them.

---

## 5. Limits

### 5.1 Schema

```json
"limits": {
  "resources": ["/reports/*", "repo:acme/website"],
  "spend": { "unit": "USD-cents", "per_call": 2000, "total": 5000 },
  "rate": { "count": 10, "per": 60 },
  "uses": 100
}
```

| Field | Rules |
|---|---|
| `resources` | 1–32 patterns of at most 256 characters, with no whitespace or control characters (C0, DEL and C1: U+0000–U+001F, U+007F–U+009F). A `*` may appear only as the last character, meaning prefix match. "Whitespace" means Python's `str.isspace()`. |
| `spend.unit` | Required if `spend` is present. 1–64 characters, no whitespace or control characters (as above). |
| `spend.per_call`, `spend.total` | Positive integers ≤ 2⁵³−1. At least one is required. |
| `rate.count`, `rate.per` | Positive integers ≤ 2⁵³−1. `per` is at most 86400 seconds. |
| `uses` | Positive integer ≤ 2⁵³−1 |

Any other top-level field makes the grant **invalid**, so a limit a verifier doesn't understand is never silently ignored.

### 5.2 Narrowing (child vs parent)

For each limit the parent has, the child MUST also have it and MUST be at least as strict:

- **resources:** every child pattern is covered by some parent pattern. A parent pattern `x*` covers a child pattern `c` if `c` starts with `x`. An exact parent pattern covers only itself.
- **spend:** same unit; `child.per_call ≤ parent.per_call`; `child.total ≤ parent.total`.
- **rate:** `child.count × parent.per ≤ parent.count × child.per`, meaning the child's rate is no faster.
- **uses:** `child.uses ≤ parent.uses`.

Issuers SHOULD copy any limit the child leaves unset from the parent, so every grant is self-describing.

### 5.3 Enforcement per call

A service declares, per endpoint, the `resource` the call touches (optional), the `amount` it costs (a non-negative integer, default 0) and the `unit` of that amount. For **every link** in the chain:

- If the link has `resources`:
  - the endpoint MUST declare a resource, otherwise reject (fail closed);
  - reject resources that contain `*`, control characters (C0, DEL, C1), or a `.` or `..` path segment (`\` counts as a separator);
  - the resource MUST match one of the link's patterns.
- If the link has `spend` and `amount > 0`:
  - `unit` MUST equal `spend.unit`;
  - `amount ≤ per_call` and `amount ≤ total`.

### 5.4 Stateful counters

`spend.total`, `rate` and `uses` are tracked per `(iss, id)`. For each call, the verifier atomically, across **all** links that carry any of them:

- checks that spent + `amount` ≤ `total`, that uses + 1 ≤ `uses`, and that fewer than `rate.count` calls fall inside the last `rate.per` seconds;
- if every link passes, records the call on every link. If any fails, it records nothing.

Status codes: budget exhausted → 402; uses exhausted → 403; rate limit reached → 429. Refunds MAY return spend (not uses or rate) to every link, but never more than the request was charged.

The counters MUST be shared (and the check-and-charge atomic) across every process enforcing limits for the same grants; otherwise N processes allow N× the limit. A verifier that can't reach its counter store MUST reject the call. Counters for a grant MAY be discarded once `exp + 60` has passed.

---

## 6. Revocation

```json
{
  "body": { "v": "agentauth-revocation/1", "grant": "<grant id>", "iss": "<issuer DID>", "ts": 1790431700 },
  "sig": "<b64u, by the issuer's current key over canonical_json(body)>"
}
```

- Revocations are keyed by `(iss, grant)`. A revocation signed by X only ever revokes grants **issued by X**, so it can't touch anyone else's grants.
- Revoking a grant invalidates every chain that includes it, which means every delegation beneath it.
- Revocation is permanent.
- The body has exactly the fields `v, grant, iss, ts`; `grant` follows the grant-id format (§4.1), `iss` is an agent DID and `ts` an integer in [0, 2⁵³−1]. The envelope has exactly `body` and `sig`.

### 6.1 Revocation proofs

The signed revocation event *is* the proof. A registry that reports a grant as revoked (§7, `POST /v1/revocations/check`) returns the corresponding events in `proofs`. A relying party SHOULD verify each one: the body names the same `(iss, grant)`, and `sig` verifies against **some key the issuer has held** (from the issuer's verified log, including keys rotated away since). A claim without a valid proof is either treated as revoked anyway (fail closed, the reference default) or ignored (when a registry falsely revoking grants is the bigger risk); either way it should be logged.

A proof can only show that something *was* revoked. A registry can still hide a revocation; §7.1 describes how to require several registries to collude for that.

---

## 7. Registry HTTP API

All bodies are JSON. Errors are `{"detail": "<message>"}`. Every response carries an `X-Request-ID` header (echoed from the request when it's 1–64 safe characters, generated otherwise).

| Method & path | Body / query | Success | Errors |
|---|---|---|---|
| `POST /v1/identities` | Inception event (§2.2) | `201` resolution result | `400` invalid, or controller not active with the countersigning key (re-checked atomically with the insert); `401` registration token required; `409` already registered |
| `GET /v1/identities` | `?after=<did>&limit=<1-1000>` | `200` `{"identities": [{"did","active"}], "next": <did or null>}` | `400` |
| `POST /v1/identities/{did}/events` | Rotation or deactivation event | `200` resolution result | `400` invalid, or the identity already has 10,000 events; `404` unknown DID; `409` concurrent update |
| `GET /v1/identities/{did}` | — | `200` resolution result (`Cache-Control: max-age=30` by default) | `404` |
| `GET /v1/identities/{did}/log` | — | `200` `{"did", "events": [ … ]}` | `404` |
| `GET /v1/identities/{did}/agents` | `?after=<did>&limit=<1-1000>` | `200` `{"controller", "agents": [{"did","active"}], "next"}` | `400` |
| `POST /v1/revocations` | Revocation (§6) | `201` `{"issuer","grant","revoked":true,"new":bool}` | `400` invalid or issuer inactive |
| `POST /v1/revocations/check` | `{"grants": [[iss, id], …]}` (max 32) | `200` `{"revoked": [[iss, id], …], "proofs": [event, …]}` (`proofs[i]` proves `revoked[i]`) | `400` |
| `GET /v1/whoami` | — (requires `AgentSig`) | `200` `{"did","kid"}` | `401`, `503` |
| `GET /v1/info` | — | `200` `{"software","version","protocols","schema_version","registration","max_event_bytes"}` | — |
| `GET /healthz` | — | `200` `{"ok": true}` (liveness) | — |
| `GET /readyz` | — | `200` `{"ok": true, "checks": {...}}` (database, Redis) | `503` when a dependency is down or the schema isn't current |
| `GET /metrics` | — | `200` Prometheus text format (can be disabled) | — |

- A path `{did}` that isn't a `did:agent:` identifier answers `404`.
- Request bodies larger than the configured limit (default 16 KiB) are rejected with `413` before they are read; events larger than 16 KiB always are. A body that takes longer than 10 s to arrive is rejected with `408`.
- `/v1/*` routes are rate-limited per client address (defaults: 60 writes and 1200 reads per minute; `/v1/revocations/check` counts as a read). IPv6 clients are counted per /64. Over the limit: `429` with `Retry-After`.
- A temporarily unavailable database (lock or pool timeout, lost connection) answers `503` with `Retry-After`. Retry it.
- The registry serves no interactive docs or OpenAPI schema (`/docs`, `/redoc` and `/openapi.json` answer `404`); this section is the API reference.
- When the operator sets a registration token, `POST /v1/identities` requires the header `X-AgentAuth-Registration-Token`. Key events and revocations never need it: they are authorized by the identity's own signatures.
- `proofs` was added in v0.4. Clients MUST tolerate its absence (older registries).

### 7.1 Several registries

Nothing in the protocol ties an identity to one registry. A client MAY submit events to several independent registries and, when resolving, fetch the log from each. A client MUST verify each registry's log on its own (including controller key binding, §2.2) and ignore any that fails, so a registry serving an invalid but longer log can't win. Logs from honest registries are prefixes of one another (one may lag); a client MUST treat two valid logs that differ at the same `seq` as **equivocation** and fail closed, and SHOULD use the longest log otherwise. A client SHOULD also remember the newest `(seq, digest)` it has verified for each DID and reject any later log that is shorter or differs at that position. The reference implementation provides both (`RegistryPool`, `KelPins`).

---

## 8. Version strings and constants

| Name | Value |
|---|---|
| Identity event version | `agentauth/1` |
| DID method prefix | `did:agent:` |
| Request signing string tag | `agentauth-request/1` |
| Grant version | `agentauth-grant/1` |
| Revocation version | `agentauth-revocation/1` |
| Authorization scheme | `AgentSig` |
| Grant header | `AgentGrant` |
| Request clock skew | 120 s |
| Nonce replay window | 241 s |
| Nonce length | 16–128 characters |
| `Authorization` header | ≤ 4096 bytes |
| `AgentGrant` header | ≤ 32 KiB |
| Largest integer in any signed number | 2⁵³ − 1 |
| Grant clock skew | 60 s |
| Default grant TTL | 900 s |
| Maximum grant TTL | 86400 s |
| Maximum chain length | 8 |
| Event nesting (envelope included) | ≤ 24 levels |
| `meta` nesting | ≤ 16 levels |
| Grant body nesting | ≤ 8 levels |
| Events per identity (reference registry) | ≤ 10,000 |

---

## 9. Changes in v0.4

Formats and version strings are unchanged. Verification is stricter; every item below rejects input that v0.3 accepted:

| Area | v0.4 rule |
|---|---|
| base64url | Only the canonical unpadded encoding is accepted (§1.1) |
| JSON | Lone surrogates can't be canonicalized; the registry rejects duplicate keys and `NaN`/`Infinity` |
| Events | Exact field sets for bodies and envelopes; `ts` format; `next` must be a well-formed digest; `controller_proof` only on inception with a controller; `meta` nested ≤ 16 levels (§2) |
| `AgentSig` | No duplicate parameters; `ts`, `nonce`, `did`, `kid`, `aud` formats; header ≤ 4096 bytes (§3.1) |
| Request path | Verified against the raw request target. (v0.3's FastAPI integration verified the *decoded* path, so requests to URLs with percent-encoding failed.) |
| Grants | No unknown fields; formats for ids, DIDs, `kid`, audiences; `iss != sub`; no duplicate links; integers ≤ 2⁵³−1 (§4) |
| Limits | Upper bounds on numbers and `spend.unit` (§5.1); refunds can't exceed the amount charged |
| Revocations | Exact field sets and formats (§6) |
| Failures | A dependency failure during verification rejects the request with 503 |
| Inception | `next` may not commit to the current key (§2.2); events nested deeper than 24 levels or holding integers beyond 2⁵³−1 are rejected before hashing |
| Controller keys | Clients replaying logs bind controller signatures to the controller's verified key history (§2.2) |
| Grant encoding | The payload must be exactly `canonical_json(body)`: no duplicate keys, floats or alternative spellings; nesting ≤ 8 (§4.2) |
| Grant fields | Audiences and scopes are printable ASCII; `aud` and `scope` must already be sorted, de-duplicated and (for `aud`) lower-cased; stateful limits can't use audience `"*"` (§4.1) |
| Limits | DEL and C1 control characters are rejected in patterns, units and requested resources (§5.1, §5.3) |

The last five rows came out of the October 2026 internal security review ([security-audit-2026-10.md](security-audit-2026-10.md)). A grant issued by the v0.3 or v0.4 reference SDK still verifies, unless it uses a non-ASCII audience or scope, or a budget, rate or use limit on audience `"*"`.
