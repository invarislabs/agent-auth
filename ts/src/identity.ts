/**
 * Key event log verification (protocol §2): self-certifying DIDs, hash
 * chaining, mandatory pre-rotation, controller countersignatures and
 * deactivation. A port of `agentauth.identity`, check for check.
 */

import { digest, isDigest, keyCommitment, multikeyToPublicKey, verify } from "./crypto.js";
import { InvalidEvent } from "./errors.js";
import { CanonicalizationError, canonicalJson, isObject, type JsonObject } from "./json.js";

export const VERSION = "agentauth/1";
export const DID_PREFIX = "did:agent:";
const DID_RE = /^did:agent:[1-9A-HJ-NP-Za-km-z]{40,60}$/;
const TS_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const INCEPTION_FIELDS = ["v", "type", "seq", "prev", "key", "next", "controller", "meta", "ts", "did"];
const UPDATE_FIELDS = ["v", "type", "did", "seq", "prev", "key", "next", "ts"];
const ENVELOPE_FIELDS = new Set(["body", "signer", "sig", "controller_proof"]);
export const MAX_META_DEPTH = 16;
/** Envelope -> body -> meta leaves room for MAX_META_DEPTH levels of meta. */
export const MAX_EVENT_DEPTH = 24;

/** (controller DID, multikey) -> may that key act for the controller? */
export type ControllerKeyCheck = (did: string, key: string) => boolean | Promise<boolean>;

/** Checks signatures only, not that the key belonged to the controller (same default as Python's verify_log). */
export const trustEmbeddedControllerKeys: ControllerKeyCheck = () => true;

export interface IdentityState {
  did: string;
  seq: number;
  key: string | null;
  next: string | null;
  controller: string | null;
  meta: JsonObject;
  active: boolean;
  created: string;
  updated: string;
  lastDigest: string;
  keySeq: number;
  history: Array<[number, string]>;
}

export const keyId = (s: IdentityState): string => `${s.did}#key-${s.keySeq}`;

export function isAgentDid(value: unknown): value is string {
  return typeof value === "string" && DID_RE.test(value);
}

function require(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new InvalidEvent(msg);
}

function canonical(body: unknown): Uint8Array {
  try {
    return canonicalJson(body);
  } catch (e) {
    if (e instanceof CanonicalizationError) throw new InvalidEvent(`event is not canonicalizable: ${e.message}`);
    throw e;
  }
}

export async function eventDigest(event: JsonObject): Promise<string> {
  return digest(canonical(event["body"]));
}

async function didFromInception(body: JsonObject): Promise<string> {
  const unsigned: JsonObject = Object.create(null);
  for (const [k, v] of Object.entries(body)) if (k !== "did") unsigned[k] = v;
  return DID_PREFIX + (await digest(canonical(unsigned))).slice(1);
}

function depth(obj: unknown, limit: number): number {
  let deepest = 0;
  const stack: Array<[unknown, number]> = [[obj, 1]];
  while (stack.length) {
    const [o, d] = stack.pop()!;
    if (Array.isArray(o) || isObject(o)) {
      if (d > limit) return d;
      deepest = Math.max(deepest, d);
      for (const v of Array.isArray(o) ? o : Object.values(o)) stack.push([v, d + 1]);
    }
  }
  return deepest;
}

/** Bounded nesting and only integers every JSON implementation represents exactly (no bigint). */
export function shapeOk(obj: unknown, limit: number): boolean {
  const stack: Array<[unknown, number]> = [[obj, 1]];
  while (stack.length) {
    const [o, d] = stack.pop()!;
    if (Array.isArray(o) || isObject(o)) {
      if (d > limit) return false;
      for (const v of Array.isArray(o) ? o : Object.values(o)) stack.push([v, d + 1]);
    } else if (typeof o === "bigint" || (typeof o === "number" && Number.isInteger(o) && !Number.isSafeInteger(o))) {
      return false;
    }
  }
  return true;
}

function sameKeys(o: JsonObject, fields: string[]): boolean {
  const keys = Object.keys(o);
  return keys.length === fields.length && fields.every((f) => Object.prototype.hasOwnProperty.call(o, f));
}

function checkEnvelope(event: unknown): JsonObject {
  require(isObject(event), "event must be an object");
  require(shapeOk(event, MAX_EVENT_DEPTH), `event nests deeper than ${MAX_EVENT_DEPTH} levels or holds an integer beyond 2**53-1`);
  require(Object.keys(event).every((k) => ENVELOPE_FIELDS.has(k)), "event envelope has unknown fields");
  require(typeof event["signer"] === "string", "signer must be a string");
  require(typeof event["sig"] === "string", "sig must be a string");
  const body = event["body"];
  require(isObject(body), "event body must be an object");
  return body;
}

function checkCommon(body: JsonObject, fields: string[]): void {
  require(body["v"] === VERSION, `unsupported version ${JSON.stringify(body["v"])}`);
  require(sameKeys(body, fields), "event body has missing or unknown fields");
  const seq = body["seq"];
  require(typeof seq === "number" && Number.isInteger(seq) && seq >= 0, "seq must be a non-negative int");
  require(typeof body["ts"] === "string" && TS_RE.test(body["ts"]), "ts must be an RFC 3339 UTC timestamp");
  try {
    multikeyToPublicKey(body["key"]);
  } catch (e) {
    throw new InvalidEvent(`bad key: ${(e as Error).message}`);
  }
}

export async function verifyInception(event: unknown, controllerCheck: ControllerKeyCheck): Promise<IdentityState> {
  const body = checkEnvelope(event);
  const ev = event as JsonObject;
  const sig = ev["sig"] as string;
  require(body["type"] === "inception", "first event must be an inception");
  checkCommon(body, INCEPTION_FIELDS);
  require(body["seq"] === 0 && body["prev"] === null, "inception must have seq=0, prev=null");
  require(isDigest(body["next"]), "inception must commit to a next key (pre-rotation)");
  require((await keyCommitment(body["key"] as string)) !== body["next"], "next key must differ from current key");
  require(isObject(body["meta"]), "meta must be an object");
  require(depth(body["meta"], MAX_META_DEPTH) <= MAX_META_DEPTH, `meta may nest at most ${MAX_META_DEPTH} levels`);
  const msg = canonical(body);
  require(body["did"] === (await didFromInception(body)), "DID does not match inception digest");
  const did = body["did"] as string;
  require(ev["signer"] === did, "inception must be self-signed");
  const ctrl = body["controller"];
  require(ctrl === null || (isAgentDid(ctrl) && ctrl !== did), "controller must be another agent DID");
  require(await verify(body["key"], msg, sig), "bad inception signature");
  if (ctrl !== null) {
    const proof = ev["controller_proof"];
    if (!isObject(proof) || !sameKeys(proof, ["key", "sig"])) throw new InvalidEvent("missing or bad controller countersignature");
    require(await verify(proof["key"], msg, proof["sig"]), "missing or bad controller countersignature");
    require(await controllerCheck(ctrl as string, proof["key"] as string), "controller countersignature is not from a valid controller key");
  } else {
    require(!("controller_proof" in ev), "controller_proof without a controller");
  }
  return {
    did,
    seq: 0,
    key: body["key"] as string,
    next: body["next"] as string,
    controller: ctrl as string | null,
    meta: body["meta"] as JsonObject,
    active: true,
    created: body["ts"] as string,
    updated: body["ts"] as string,
    lastDigest: await eventDigest(ev),
    keySeq: 0,
    history: [[0, body["key"] as string]],
  };
}

/** Validate `event` against `state` and return the new state (pure). */
export async function applyEvent(state: IdentityState, event: unknown, controllerCheck: ControllerKeyCheck): Promise<IdentityState> {
  const body = checkEnvelope(event);
  const ev = event as JsonObject;
  const sig = ev["sig"] as string;
  const signer = ev["signer"] as string;
  require(!("controller_proof" in ev), "controller_proof is only valid on inception");
  require(body["type"] === "rotation" || body["type"] === "deactivation", `unknown event type ${JSON.stringify(body["type"])}`);
  checkCommon(body, UPDATE_FIELDS);
  require(state.active, "identity is deactivated");
  require(body["did"] === state.did, "event is for a different DID");
  require(body["seq"] === state.seq + 1, `expected seq ${state.seq + 1}, got ${String(body["seq"])}`);
  require(body["prev"] === state.lastDigest, "prev digest does not chain to the log");
  const msg = canonical(body);
  const key = body["key"] as string;
  const next: IdentityState = {
    ...state,
    history: [...state.history],
    seq: body["seq"] as number,
    updated: body["ts"] as string,
    lastDigest: await eventDigest(ev),
  };

  if (body["type"] === "rotation") {
    require(signer === state.did, "rotation must be signed by the agent");
    require((await keyCommitment(key)) === state.next, "rotated key does not match pre-rotation commitment");
    require(isDigest(body["next"]), "rotation must commit to a new next key");
    require((await keyCommitment(key)) !== body["next"], "next key must differ from current key");
    require(await verify(key, msg, sig), "bad rotation signature");
    next.key = key;
    next.next = body["next"] as string;
    next.keySeq = body["seq"] as number;
    next.history.push([body["seq"] as number, key]);
    return next;
  }

  require(body["next"] === null, "deactivation must not commit to a next key");
  if (signer === state.did) {
    require((await keyCommitment(key)) === state.next, "self-deactivation must be signed with the pre-committed recovery key");
  } else {
    require(state.controller !== null && signer === state.controller, "only the agent or its controller may deactivate");
    require(await controllerCheck(signer, key), "deactivation not signed with a valid controller key");
  }
  require(await verify(key, msg, sig), "bad deactivation signature");
  next.active = false;
  next.key = null;
  next.next = null;
  return next;
}

/** Replay a full key event log and return the resulting state. */
export async function verifyLog(events: unknown, controllerCheck: ControllerKeyCheck = trustEmbeddedControllerKeys): Promise<IdentityState> {
  require(Array.isArray(events) && events.length > 0, "log is empty");
  let state = await verifyInception(events[0], controllerCheck);
  for (const ev of events.slice(1)) state = await applyEvent(state, ev, controllerCheck);
  return state;
}
