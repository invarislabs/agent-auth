# @invarislabs/agentauth (TypeScript verifier)

A TypeScript verifier for [AgentAuth](../README.md). Node, Deno, Bun, browser and edge
services can use it to check agent identities, signed requests and delegation chains
without running Python.

- **Verifies** did:agent key event logs (pre-rotation, controller countersignatures,
  deactivation), AgentSig request signatures (audience, timestamp window, replay
  cache), AgentGrant delegation chains (attenuation, limits narrowing, issuer keys,
  root policy, revocation) and revocation proofs.
- **Matches the Python reference.** Both implementations run the same test vectors in
  [`../test-vectors`](../test-vectors), so they accept and reject the same inputs with
  the same HTTP status codes.
- **Has no runtime dependencies.** It uses WebCrypto (Ed25519, SHA-256), so it needs
  Node 20 or later, or any runtime with `crypto.subtle` Ed25519.
- **Only verifies.** To create identities and issue grants, use the Python SDK or the
  `agentauth` CLI.

Status: 0.1.0. It is not on npm yet. To use it before the first release, build it from
this folder.

## Install and build

```sh
cd ts
npm ci
npm test
```

## Verify a request

```ts
import {
  RegistryClient, registryKeyResolver, registryRevocationChecker,
  RequestVerifier, GrantVerifier, trustPrincipals, checkCall, AgentAuthError,
} from "@invarislabs/agentauth";

const registry = new RegistryClient("https://registry.example.com");
const keys = registryKeyResolver(registry, { ttlSeconds: 30 });

const requests = new RequestVerifier(keys, { audiences: ["api.example.com"] });
const grants = new GrantVerifier(keys, {
  rootPolicy: trustPrincipals({ "did:agent:QmYourOrg…": ["tools.*"] }),
  revoked: registryRevocationChecker(registry),
});

async function authorize(req: Request, rawTarget: string): Promise<Response | null> {
  const body = new Uint8Array(await req.clone().arrayBuffer());
  const grantHeader = req.headers.get("AgentGrant") ?? "";
  try {
    const agent = await requests.verify({
      authorization: req.headers.get("Authorization"),
      method: req.method,
      path: rawTarget,          // raw path + query exactly as sent (percent-encoding intact)
      body,
      grants: grantHeader,
    });
    const authz = await grants.verify(grantHeader, { requester: agent.did, audience: agent.audience });
    if (!authz.allows("tools.search")) return new Response("forbidden", { status: 403 });
    checkCall(authz, { resource: "repo:acme/website" });  // stateless limits on every link
    return null; // authorized
  } catch (e) {
    if (e instanceof AgentAuthError) return Response.json({ detail: e.message }, { status: e.status });
    throw e;
  }
}
```

Every error is an `AgentAuthError` that carries the HTTP status to return:

| Status | Meaning |
|--------|---------|
| 400 | Malformed input |
| 401 | Missing or invalid signature, or no grant |
| 403 | The grant doesn't allow this request |
| 503 | A dependency (registry, replay cache, revocation check) couldn't give a safe answer |

The verifier fails closed: when it can't be sure, it refuses the request.

## What you must provide in production

- **A shared replay cache.** The default `MemoryNonceCache` works for a single process
  only. If more than one process or replica verifies requests for the same audience,
  implement `ReplayCache` on a shared store (for example Redis `SET key 1 NX EX ttl`).
  Make its `ttl` at least `2 * maxSkew + 1` seconds.
- **A ledger for stateful limits.** Grants can limit total spend, rate and number of
  uses. Those counters must be shared by every replica, so this package does not keep
  them. Check `authz.linkLimits[i].limits.stateful` and charge every link atomically,
  as the Python `UsageLedger` / `RedisUsageLedger` does.
- **The raw request target.** Sign and verify the path exactly as sent, with
  percent-encoding intact. Do not use a decoded or normalised path.

## Security properties

This package is a check-for-check port of the Python verifier. The Python
documentation describes them in full:
[protocol](../docs/protocol.md), [threat model](../docs/threat-model.md) and the
[October 2026 internal security review](../docs/security-audit-2026-10.md). Some
points matter most for the port:

- **Strict JSON parsing.** `JSON.parse` silently turns `1.0` into `1` and rounds
  integers above 2^53, so this package uses its own strict parser that keeps every
  number's type. It also requires grant payloads to be byte-for-byte canonical JSON.
  Because of this, the two implementations can never read the same token differently.
- **Python string semantics.** Python and JavaScript disagree on what whitespace is
  and how to sort strings. Where the protocol depends on either, this package follows
  Python's `str.isspace()` and code-point ordering (see `src/pystr.ts`).
- **Controller binding.** `RegistryClient.verifiedState` accepts a controller's
  signature only if the key appears in the controller's own verified log.
- **Pinning.** `KelPins` remembers every log it has seen. If a registry later serves a
  shorter (rolled-back) or forked log, the client raises `EquivocationError`.
- **No redirects.** Registry requests use `redirect: "error"`, so a registry can't send
  the client somewhere else.

## Layout

| Path | Contents |
|------|----------|
| `src/json.ts` | Strict JSON parser and canonical JSON |
| `src/crypto.ts` | base58btc, multikey, digests, strict base64url, Ed25519 verification |
| `src/identity.ts` | Key event log verification |
| `src/httpsig.ts` | AgentSig parsing and request verification |
| `src/grants.ts` | Grant chains, attenuation and revocations |
| `src/limits.ts` | Grant limits |
| `src/registry.ts` | Registry client, key resolver, revocation checker and pins |
| `test/` | Runs `../test-vectors` and tests the registry client |

## License

Apache-2.0, like the rest of the repository.
