# Protocol specification (v0.3)

This document describes AgentAuth's wire formats and verification rules precisely enough to write a compatible client or verifier in another language. The Python package is the reference implementation. If this document and the code disagree, the code wins, and the disagreement should be fixed here.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

- [1. Primitives](#1-primitives)
- [2. Identifiers and key event logs](#2-identifiers-and-key-event-logs)
- [3. Request authentication (`AgentSig`)](#3-request-authentication-agentsig)
- [4. Capability grants (`AgentGrant`)](#4-capability-grants-agentgrant)
- [5. Limits](#5-limits)
- [6. Revocation](#6-revocation)
- [7. Registry HTTP API](#7-registry-http-api)
- [8. Version strings and constants](#8-version-strings-and-constants)

---

## 1. Primitives

### 1.1 Signatures

- **Algorithm:** Ed25519 (RFC 8032).
- **Encoding:** the 64-byte signature, base64url **without padding** (`b64u`).

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

`controller_proof` appears only on inception events that name a controller.

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

1. `v == "agentauth/1"`, `type == "inception"`, `seq == 0` (an integer, not a boolean), `prev == null`, `ts` is a string.
2. `key` is a valid Ed25519 multikey.
3. `next` is a string. Pre-rotation is mandatory.
4. `did` equals the derivation above.
5. `signer == did`, and `sig` verifies against `key`.
6. `controller` is `null`, or an agent DID different from `did`.
7. `meta` is an object.
8. If `controller` is set: `controller_proof.sig` MUST verify over `canonical_json(body)` with `controller_proof.key`. A registry MUST additionally check that `controller_proof.key` is the controller's **current** key.

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
- `next` is a string, and `next != commitment(key)`;
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
- **Controller deactivation:** `signer == state.controller`, and `key` is the controller's current key. A registry checks this against live state. An auditor MAY accept any key the controller has ever held.

In both cases `sig` MUST verify against `key` and `next` MUST be `null`. After deactivation the identity has no key, and no further events are accepted.

### 2.5 Checks common to every non-inception event

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

Parameter values MUST NOT contain `"`. The nonce SHOULD have at least 128 bits of entropy (the reference client uses 16 random bytes, base64url-encoded).

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

1. Parse the header. All six parameters are required.
2. Reject if `aud` (lower-cased) is not one of its audiences.
3. Reject if `|now − ts| > max_skew`. The default is 120 s.
4. Resolve `did` to its current `(key, kid)`. Reject if unknown or deactivated. If the presented `kid` has a **higher** key sequence than the cached one, the verifier SHOULD refresh its cache once before rejecting.
5. Reject if the presented `kid` isn't the current `kid`.
6. Verify `sig` over the signing string, using the verifier's own view of method, path, body and `AgentGrant` header.
7. Reject if `(did, nonce)` has been seen within the replay window (at least 2 × `max_skew`). Record the nonce **only after** the signature verifies.

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

- `scope` and `aud` are sorted and de-duplicated, and `aud` is lower-cased.
- `limits` is omitted when there are no limits (see §5).

### 4.2 Encoding

```
grant  = b64u(canonical_json(body)) + "." + b64u(signature over canonical_json(body))
header = grant_root "," grant_1 "," … "," grant_leaf          (at most 8 links)
```

The header name is `AgentGrant`.

### 4.3 Scopes

- A scope is a non-empty string of at most 128 characters with no whitespace.
- `*` may only appear as the whole scope (`"*"`) or as a trailing `.*` (`"tools.*"`).
- `covers(p, c)` holds when `p == "*"`, or `p == c`, or `p` ends in `.*` and `c` starts with `p` minus the `*` and `c != that prefix`. So `tools.*` covers `tools.search` and `tools.*`, but not `tools`.
- A set of scopes P covers a set C if every `c` in C is covered by some `p` in P.

### 4.4 Audiences

A set of audiences P covers C if `"*"` is in P, or every element of C is in P (compared case-insensitively).

### 4.5 Verification

Given the `AgentGrant` header, the authenticated requester DID `R`, and the request audience `A`, a verifier MUST:

For each link `g[i]`, root first:

1. Check `v`, and that `id`, `iss`, `kid`, `sub` are strings, `scope` and `aud` are lists, and `nbf`, `exp`, `depth` are integers (not booleans).
2. Check that every scope is valid (§4.3).
3. Check `nbf − 60 ≤ now < exp + 60`, and `exp − nbf ≤ 86400`.
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
| `resources` | 1–32 patterns of at most 256 characters, with no whitespace or control characters. A `*` may appear only as the last character, meaning prefix match. |
| `spend.unit` | Non-empty string. Required if `spend` is present. |
| `spend.per_call`, `spend.total` | Positive integers. At least one is required. |
| `rate.count`, `rate.per` | Positive integers. `per` is at most 86400 seconds. |
| `uses` | Positive integer |

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
  - reject resources that contain `*`, control characters, or a `.` or `..` path segment;
  - the resource MUST match one of the link's patterns.
- If the link has `spend` and `amount > 0`:
  - `unit` MUST equal `spend.unit`;
  - `amount ≤ per_call` and `amount ≤ total`.

### 5.4 Stateful counters

`spend.total`, `rate` and `uses` are tracked per `(iss, id)`. For each call, the verifier atomically, across **all** links that carry any of them:

- checks that spent + `amount` ≤ `total`, that uses + 1 ≤ `uses`, and that fewer than `rate.count` calls fall inside the last `rate.per` seconds;
- if every link passes, records the call on every link. If any fails, it records nothing.

Status codes: budget exhausted → 402; uses exhausted → 403; rate limit reached → 429. Refunds MAY return spend (not uses or rate) to every link.

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

---

## 7. Registry HTTP API

All bodies are JSON. Errors are `{"detail": "<message>"}`.

| Method & path | Body | Success | Errors |
|---|---|---|---|
| `POST /v1/identities` | Inception event (§2.2) | `201` resolution result | `400` invalid, or controller not active; `409` already registered |
| `POST /v1/identities/{did}/events` | Rotation or deactivation event | `200` resolution result | `400` invalid; `404` unknown DID; `409` concurrent update |
| `GET /v1/identities/{did}` | — | `200` resolution result (`Cache-Control: max-age=30`) | `404` |
| `GET /v1/identities/{did}/log` | — | `200` `{"did", "events": [ … ]}` | `404` |
| `GET /v1/identities/{did}/agents` | — | `200` `{"controller", "agents": [{"did","active"}]}` | — |
| `POST /v1/revocations` | Revocation (§6) | `201` `{"issuer","grant","revoked":true,"new":bool}` | `400` invalid or issuer inactive |
| `POST /v1/revocations/check` | `{"grants": [[iss, id], …]}` (max 32) | `200` `{"revoked": [[iss, id], …]}` | `400` |
| `GET /v1/whoami` | — (requires `AgentSig`) | `200` `{"did","kid"}` | `401` |
| `GET /healthz` | — | `200` `{"ok": true}` | — |

Event bodies larger than 16 KiB are rejected with `413`.

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
| Nonce replay window | 240 s |
| Grant clock skew | 60 s |
| Default grant TTL | 900 s |
| Maximum grant TTL | 86400 s |
| Maximum chain length | 8 |
