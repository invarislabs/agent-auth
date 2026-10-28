/** Errors carry the HTTP status a service should answer with, mirroring the Python reference. */

export class AgentAuthError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = new.target.name;
    this.status = status;
  }
}

/** Request authentication failed (401), or a dependency failed during it (503). */
export class AuthError extends AgentAuthError {
  constructor(message: string, status = 401) {
    super(message, status);
  }
}

/** A grant chain was refused (403), malformed (400), absent (401), or couldn't be checked (503). */
export class GrantError extends AgentAuthError {
  constructor(message: string, status = 403) {
    super(message, status);
  }
}

/** A limit is malformed (400) or a call exceeds it (403). */
export class LimitError extends AgentAuthError {
  constructor(message: string, status = 403) {
    super(message, status);
  }
}

/** A key event or key event log failed verification. */
export class InvalidEvent extends AgentAuthError {
  constructor(message: string) {
    super(message, 400);
  }
}

/** A registry served a log inconsistent with one verified earlier (rollback or fork). */
export class EquivocationError extends AgentAuthError {
  readonly did: string;
  constructor(did: string, message: string) {
    super(`${did}: ${message}`, 503);
    this.did = did;
  }
}
