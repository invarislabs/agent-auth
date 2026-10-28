/**
 * Grant limits (protocol §5): parsing (unknown limits fail closed), narrowing
 * between parent and child, and the stateless per-call checks. Stateful
 * counters (spend totals, rates, uses) need a shared ledger and are the
 * service's job; `stateful` tells you whether a link has any.
 */

import { MAX_SAFE_INT } from "./crypto.js";
import { LimitError } from "./errors.js";
import { compareCodePoints, isObject } from "./json.js";
import { isControl, isSpace } from "./pystr.js";

export const MAX_RESOURCES = 32;
export const MAX_RESOURCE_LEN = 256;
export const MAX_UNIT_LEN = 64;

const isSpaceOrControl = (c: string): boolean => isSpace(c) || isControl(c);

function validPattern(p: unknown): p is string {
  if (typeof p !== "string") return false;
  const cps = [...p];
  return cps.length > 0 && cps.length <= MAX_RESOURCE_LEN && !p.slice(0, -1).includes("*") && !cps.some(isSpaceOrControl);
}

function unsafeResource(r: unknown): boolean {
  if (typeof r !== "string" || !r || [...r].length > 4 * MAX_RESOURCE_LEN || r.includes("*")) return true;
  if ([...r].some(isControl)) return true;
  return r.replace(/\\/g, "/").split("/").some((seg) => seg === ".." || seg === ".");
}

export function patternMatches(pattern: string, resource: string): boolean {
  return pattern.endsWith("*") ? resource.startsWith(pattern.slice(0, -1)) : resource === pattern;
}

/** Does every resource matched by `child` also match `parent`? */
export function patternCovers(parent: string, child: string): boolean {
  return parent.endsWith("*") ? child.startsWith(parent.slice(0, -1)) : child === parent;
}

function posInt(v: unknown, name: string): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v <= 0 || v > MAX_SAFE_INT) {
    throw new LimitError(`${name} must be a positive integer (at most 2**53-1)`, 400);
  }
  return v;
}

const sortedUnique = (xs: string[]): string[] => [...new Set(xs)].sort(compareCodePoints);

export class Limits {
  readonly resources: string[] | null = null;
  readonly spendUnit: string | null = null;
  readonly perCall: number | null = null;
  readonly total: number | null = null;
  readonly rateCount: number | null = null;
  readonly ratePer: number | null = null;
  readonly uses: number | null = null;

  constructor(init: Partial<Limits> = {}) {
    Object.assign(this, init);
  }

  static fromDict(d: unknown): Limits {
    if (d === null || d === undefined) return new Limits();
    if (!isObject(d)) throw new LimitError("limits must be an object", 400);
    const unknown = Object.keys(d).filter((k) => !["resources", "spend", "rate", "uses"].includes(k));
    if (unknown.length) throw new LimitError(`unknown limit(s): ${unknown.sort().join(", ")}`, 400);
    const kw: Record<string, unknown> = {};
    if ("resources" in d) {
      const rs = d["resources"];
      if (!Array.isArray(rs) || !rs.length || rs.length > MAX_RESOURCES || !rs.every(validPattern)) {
        throw new LimitError("resources must be 1-32 patterns (exact, or ending in *)", 400);
      }
      kw["resources"] = sortedUnique(rs as string[]);
    }
    if ("spend" in d) {
      const sp = d["spend"];
      if (!isObject(sp) || Object.keys(sp).some((k) => !["unit", "per_call", "total"].includes(k))) {
        throw new LimitError("spend must be {unit, per_call?, total?}", 400);
      }
      const u = sp["unit"];
      if (typeof u !== "string" || !u || [...u].length > MAX_UNIT_LEN || [...u].some(isSpaceOrControl)) {
        throw new LimitError("spend.unit is required (1-64 characters, no whitespace)", 400);
      }
      if (!("per_call" in sp) && !("total" in sp)) throw new LimitError("spend needs per_call and/or total", 400);
      kw["spendUnit"] = u;
      if ("per_call" in sp) kw["perCall"] = posInt(sp["per_call"], "spend.per_call");
      if ("total" in sp) kw["total"] = posInt(sp["total"], "spend.total");
    }
    if ("rate" in d) {
      const rt = d["rate"];
      const keys = isObject(rt) ? Object.keys(rt).sort() : [];
      if (!isObject(rt) || keys.length !== 2 || keys[0] !== "count" || keys[1] !== "per") {
        throw new LimitError("rate must be {count, per}", 400);
      }
      kw["rateCount"] = posInt(rt["count"], "rate.count");
      kw["ratePer"] = posInt(rt["per"], "rate.per");
      if ((kw["ratePer"] as number) > 86400) throw new LimitError("rate.per may be at most 86400 seconds", 400);
    }
    if ("uses" in d) kw["uses"] = posInt(d["uses"], "uses");
    return new Limits(kw as Partial<Limits>);
  }

  get stateful(): boolean {
    return this.total !== null || this.rateCount !== null || this.uses !== null;
  }

  /** Why `child` would loosen these limits, or null if it only tightens them. */
  narrowingViolation(child: Limits): string | null {
    if (this.resources !== null) {
      if (child.resources === null) return "child drops the parent's resource restriction";
      for (const c of child.resources) {
        if (!this.resources.some((p) => patternCovers(p, c))) return `resource ${JSON.stringify(c)} is outside the parent's`;
      }
    }
    if (this.spendUnit !== null) {
      if (child.spendUnit !== null && child.spendUnit !== this.spendUnit) return "spend unit differs from the parent's";
      if (this.perCall !== null && (child.perCall === null || child.perCall > this.perCall)) return "per-call spend exceeds the parent's";
      if (this.total !== null && (child.total === null || child.total > this.total)) return "spend total exceeds the parent's";
    }
    if (this.rateCount !== null) {
      if (child.rateCount === null) return "child drops the parent's rate limit";
      // child.count / child.per <= parent.count / parent.per, in exact integer arithmetic
      if (BigInt(child.rateCount) * BigInt(this.ratePer ?? 1) > BigInt(this.rateCount) * BigInt(child.ratePer ?? 1)) {
        return "rate exceeds the parent's";
      }
    }
    if (this.uses !== null && (child.uses === null || child.uses > this.uses)) return "use count exceeds the parent's";
    return null;
  }

  /** Stateless checks for one call: resources and per-call spend. */
  checkCall({ resource, amount = 0, unit = null }: { resource?: string | null; amount?: number; unit?: string | null }): void {
    if (this.resources !== null) {
      if (resource === null || resource === undefined) {
        throw new LimitError("grant is limited to specific resources, but this endpoint names none");
      }
      if (unsafeResource(resource)) throw new LimitError("requested resource is not a plain name (no '..', '.', '*')", 400);
      if (!this.resources.some((p) => patternMatches(p, resource))) {
        throw new LimitError(`grant does not cover resource ${JSON.stringify(resource)}`);
      }
    }
    if (this.spendUnit !== null && amount) {
      if (unit !== this.spendUnit) throw new LimitError(`grant spends in ${this.spendUnit}, endpoint charges in ${String(unit)}`);
      if (this.perCall !== null && amount > this.perCall) throw new LimitError(`amount ${amount} exceeds per-call limit ${this.perCall}`);
      if (this.total !== null && amount > this.total) throw new LimitError(`amount ${amount} exceeds total budget ${this.total}`);
    }
  }
}
