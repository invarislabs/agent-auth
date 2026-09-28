# Why AgentAuth

## The short version

AI agents are starting to act on their own: calling APIs, spending money, reading files, and handing work to other agents. The ways we authenticate software today were built for two kinds of caller, **humans** (who log in) and **services** (which a team deploys and owns). Autonomous agents are neither. They're created on the fly, run where you can't fully see, delegate to each other, and act *on behalf of* someone.

AgentAuth gives each agent a **cryptographic identity it owns**, lets it **prove who it is on every request without sharing a secret**, and lets a human **hand it a limited, revocable slice of their authority**. That slice can be passed down to sub-agents, but it can only shrink along the way.

## What goes wrong today

### API keys are the wrong shape

Most agents today authenticate with an API key pasted into an environment variable. That causes predictable problems:

- **Keys leak.** Agents put their context everywhere: logs, prompts, tool outputs, traces, other agents' memories. A bearer secret in an agent's context is one prompt injection away from being exfiltrated.
- **A leaked key works anywhere, forever.** Nothing ties it to a particular request, service or time window.
- **Keys identify an account, not an agent.** When ten agents share a key, you can't tell which one did something, and you can't turn off just one.
- **No delegation.** If an agent needs to hand a subtask to a sub-agent, its only option is to share the key, giving away all of its authority.
- **No limits.** A key can do everything the account can. "This agent may spend up to 50 USD on API credits this afternoon" can't be expressed.

### OAuth helps, but assumes a human in the loop

OAuth 2.0 was designed for a *user* granting an *app* access through a browser consent screen. It's a much better fit than API keys, and ideas like scopes and short-lived tokens carry over directly. But:

- **Tokens are bearer credentials.** Whoever holds one can use it. There are proof-of-possession extensions (DPoP, mTLS-bound tokens), but they aren't the default and the tooling is uneven.
- **Delegation chains aren't native.** Token exchange can model "A on behalf of B", but multi-hop chains (human → agent → sub-agent → sub-sub-agent) with narrowing at each hop get complicated quickly.
- **The authorization server is the root of trust for identity.** An agent's identity is whatever the provider's database says it is.
- **Budgets, rates and use counts** aren't part of the model.

### mTLS and workload identity (SPIFFE, cloud IAM) fit infrastructure, not agents

Workload identity is great for services a platform team deploys. Agents break its assumptions:

- They're created dynamically, sometimes by other agents.
- They run across many environments: laptops, notebooks, SaaS sandboxes, other people's clouds.
- They need to carry *a human's intent*, not just "this is pod X".

## What AgentAuth does differently

| Need | AgentAuth's answer |
|---|---|
| An identity the agent owns | A **self-certifying DID**, derived from the agent's own signed key material. No registry can mint, reassign or forge it. |
| No secrets on the wire | Every request is **signed** with the agent's private key. The signature is bound to the method, path, body, target service, a timestamp and a single-use nonce, so it can't be replayed or reused elsewhere. |
| Survive key compromise | **Pre-rotation**: each identity commits to its *next* key in advance, so a stolen current key can't be used to take the identity over. |
| Know who's responsible | An optional **controller** (the human or org that owns the agent) co-signs its creation and holds a **kill switch**. |
| Act on someone's behalf | A human issues a **capability grant**: scoped, short-lived, and tied to specific services. |
| Delegate safely | Agents can re-delegate a *narrower* slice to sub-agents. Scopes, audiences, lifetime and depth can only shrink, and every action traces back to a human principal. |
| Put a ceiling on damage | **Limits** on resources, per-call and total spend, rate, and number of uses. Budgets are shared across everything delegated beneath a grant. |
| Stop things quickly | **Revoke** a grant, or **deactivate** an agent, and everything downstream stops working. |
| Don't trust the middleman | Services can replay an agent's full **key event log** and verify it themselves, instead of trusting the registry's answer. |

## Who it's for

- **Teams building agents** that call third-party or internal APIs, and want something better than a shared API key.
- **Service owners** who want to accept calls from agents and know *which* agent is calling, *who* authorized it, and *what* it's allowed to do.
- **Platform and security teams** who need to answer "which agents can spend money, and on whose authority?", and need to be able to turn one off.

## What it isn't

- **Not a replacement for user login.** Humans still log in the way they do today. AgentAuth gives *them* an identity they can use to authorize agents.
- **Not a policy engine.** AgentAuth checks that a request is within the authority it was granted. Deciding *which* principals your service trusts, and for what, is your call (see `root_policy` in the [integration guide](integration-guide.md)).
- **Not production-hardened yet.** See the [threat model](threat-model.md) and [roadmap](roadmap.md) for what's still missing.
