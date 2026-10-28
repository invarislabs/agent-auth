"""`agentauth` command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from . import __version__
from .grants import GrantChain, GrantError
from .limits import LimitError, Limits
from .sdk import AgentIdentity, RegistryClient, RegistryError, _default_passphrase
from .witness import EquivocationError, RegistryPool

DEFAULT_REGISTRY = os.environ.get("AGENTAUTH_REGISTRY", "http://127.0.0.1:8000")
DEFAULT_DIR = os.environ.get("AGENTAUTH_HOME", "~/.agentauth")


def _out(obj) -> None:
    print(json.dumps(obj, indent=2))


def _load(args, name: str) -> AgentIdentity:
    return AgentIdentity.load(Path(args.dir), name, recovery_dir=args.recovery_dir)


def _save(args, ident: AgentIdentity, name: str) -> None:
    if not _default_passphrase():
        print("warning: key files are stored unencrypted; set AGENTAUTH_PASSPHRASE (or "
              "AGENTAUTH_PASSPHRASE_FILE) to encrypt them", file=sys.stderr)
    ident.save(Path(args.dir), name, recovery_dir=args.recovery_dir)


def cmd_init(args, reg: RegistryClient):
    key_path = Path(args.dir).expanduser() / f"{args.name}.key.json"
    if key_path.exists():
        sys.exit(f"error: {key_path} already exists")
    controller = _load(args, args.controller) if args.controller else None
    meta = dict(kv.split("=", 1) for kv in args.meta)
    ident, event = AgentIdentity.create(name=args.name, controller=controller, meta=meta)
    if not args.offline:
        reg.register(event)
    _save(args, ident, args.name)
    if args.offline:
        (key_path.parent / f"{args.name}.inception.json").write_text(json.dumps(event, indent=2))
    _out({"did": ident.did, "kid": ident.kid, "registered": not args.offline, "keys": str(key_path.parent)})


def cmd_register(args, reg: RegistryClient):
    path = Path(args.dir).expanduser() / f"{args.name}.inception.json"
    _out(reg.register(json.loads(path.read_text())))


def cmd_show(args, reg):
    ident = _load(args, args.name)
    _out({"did": ident.did, "kid": ident.kid, "key": ident.state.key, "active": ident.state.active,
          "seq": ident.state.seq, "controller": ident.state.controller, "meta": ident.state.meta,
          "can_rotate": ident.recovery_key is not None})


def cmd_resolve(args, reg: RegistryClient):
    if args.verify:
        st = reg.verified_state(args.did)
        res = st.resolution_result()
        res["verified"] = "full key event log replayed locally"
        _out(res)
    else:
        _out(reg.resolve(args.did))


def cmd_log(args, reg: RegistryClient):
    _out(reg.log(args.did))


def cmd_rotate(args, reg: RegistryClient):
    ident = _load(args, args.name)
    old = ident.kid
    resumed = ident.pending_next_key is not None
    if not _default_passphrase():
        print("warning: key files are stored unencrypted; set AGENTAUTH_PASSPHRASE to encrypt them", file=sys.stderr)
    ident.rotate_and_save(reg, Path(args.dir), args.name, recovery_dir=args.recovery_dir)
    _out({"did": ident.did, "old_kid": old, "new_kid": ident.kid, "resumed_unfinished_rotation": resumed})


def cmd_deactivate(args, reg: RegistryClient):
    if args.as_controller:
        ctrl = _load(args, args.as_controller)
        _out(reg.deactivate_controlled(ctrl, args.target))
    else:
        ident = _load(args, args.target)
        reg.deactivate_self(ident)
        _save(args, ident, args.target)
        _out({"did": ident.did, "active": False})


def cmd_agents(args, reg: RegistryClient):
    did = args.controller if args.controller.startswith("did:") else _load(args, args.controller).did
    _out(reg.controlled_agents(did))


def cmd_whoami(args, reg: RegistryClient):
    _out(reg.whoami(_load(args, args.name)))


def _read_chain(path_or_token: str) -> GrantChain:
    p = Path(path_or_token).expanduser()
    return GrantChain.decode(p.read_text().strip() if p.exists() else path_or_token)


def cmd_sign(args, reg):
    ident = _load(args, args.name)
    grants = _read_chain(args.grant).encode() if args.grant else ""
    auth = ident.authorization(args.method, args.url, (args.data or "").encode(), grants)
    if grants:
        print(f"Authorization: {auth}")
        print(f"AgentGrant: {grants}")
    else:
        print(auth)


def _subject_did(args, value: str) -> str:
    return value if value.startswith("did:") else _load(args, value).did


def cmd_grant(args, reg):
    issuer = _load(args, args.issuer)
    parent = _read_chain(args.parent) if args.parent else None
    rate = None
    if args.rate:
        try:
            count, per = args.rate.split("/")
            rate = (int(count), int(per.rstrip("s")))
        except ValueError:
            sys.exit("error: --rate must look like COUNT/SECONDS, e.g. 10/60")
    limits = Limits.build(
        resources=args.resource or None,
        spend_unit=args.unit,
        per_call=args.per_call,
        total=args.budget,
        rate=rate,
        uses=args.uses,
    )
    chain = issuer.grant(
        _subject_did(args, args.subject), args.scope, args.aud,
        ttl=args.ttl, depth=args.depth, parent=parent, limits=limits,
    )
    if args.out:
        Path(args.out).expanduser().write_text(chain.encode() + "\n")
    else:
        print(chain.encode())
    print(json.dumps({"grant_id": chain.leaf.id, "expires": chain.leaf.exp, "links": len(chain.links)}), file=sys.stderr)


def cmd_inspect(args, reg):
    _out(_read_chain(args.chain).describe())


def cmd_revoke(args, reg: RegistryClient):
    _out(reg.revoke_grant(_load(args, args.issuer), args.grant_id))


def cmd_serve(args, reg):
    import uvicorn

    from .config import Settings
    from .observability import configure_logging
    from .server import create_app

    settings = Settings.from_env()
    if args.db:
        settings.database_url = args.db
    if "AGENTAUTH_AUDIENCES" not in os.environ:
        settings.audiences = {f"{args.host}:{args.port}", f"localhost:{args.port}", f"127.0.0.1:{args.port}"}
    if args.audience:
        settings.audiences |= {a.lower() for a in args.audience}
    settings.validate()
    configure_logging(settings.log_level, settings.log_format)
    if args.workers > 1 and not settings.redis_url:
        # Each worker would keep its own replay cache, so a signed request could be replayed once per worker.
        sys.exit("error: --workers > 1 needs a shared replay cache; set AGENTAUTH_REDIS_URL")
    if args.workers > 1:
        # Each worker builds its own app from the environment.
        os.environ["AGENTAUTH_DATABASE_URL"] = settings.database_url
        os.environ["AGENTAUTH_AUDIENCES"] = ",".join(sorted(settings.audiences))
        uvicorn.run("agentauth.server:get_app", factory=True, host=args.host, port=args.port,
                    workers=args.workers, log_config=None, proxy_headers=False)
    else:
        uvicorn.run(create_app(settings=settings), host=args.host, port=args.port, log_config=None,
                    proxy_headers=False)


def _open_db(args):
    from .config import Settings
    from .store import open_store

    url = args.database_url or Settings.from_env().database_url
    return open_store(url, auto_migrate=False, check=False)


def cmd_db(args, reg):
    from .store import SCHEMA_VERSION, SchemaError

    store = _open_db(args)
    try:
        if args.action == "migrate":
            applied = store.migrate()
            _out({"applied": applied, "schema_version": store.schema_version()})
        elif args.action == "status":
            pending = store.pending_migrations()
            _out({"schema_version": store.schema_version(), "code_schema_version": SCHEMA_VERSION,
                  "pending": [{"version": v, "description": d} for v, d in pending]})
        elif args.action == "verify":
            store.check_schema()
            problems = store.verify_integrity()
            _out({"ok": not problems, "problems": problems, **store.stats()})
            if problems:
                sys.exit(1)
    except SchemaError as e:
        sys.exit(f"error: {e}")
    finally:
        store.close()


def cmd_sync(args, reg):
    if not isinstance(reg, RegistryPool):
        sys.exit("error: sync needs several registries, e.g. --registry https://a,https://b")
    _out(reg.sync(args.did))


def cmd_audit(args, reg):
    from .audit import AuditLog

    if not Path(args.path).exists():
        sys.exit(f"error: {args.path} does not exist")
    head = None
    if args.head:
        seq, _, dg = args.head.partition(":")
        head = (int(seq), dg)
    audit = AuditLog(args.path)
    problems = audit.verify(public_key=args.key, expected_head=head)
    _out({"ok": not problems, "head": audit.head(), "problems": problems})
    if problems:
        sys.exit(1)


def cmd_version(args, reg):
    _out({"agentauth": __version__})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentauth", description="Identities for autonomous AI agents")
    p.add_argument("--registry", default=DEFAULT_REGISTRY,
                   help="registry URL, or several comma-separated URLs to cross-check (env AGENTAUTH_REGISTRY)")
    p.add_argument("--dir", default=DEFAULT_DIR, help="key directory (env AGENTAUTH_HOME)")
    p.add_argument("--recovery-dir", default=None, help="where recovery (next) keys live; defaults to --dir")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="create a new agent identity and register it")
    s.add_argument("name")
    s.add_argument("--controller", help="local name of the identity that owns this agent (countersigns)")
    s.add_argument("--meta", action="append", default=[], metavar="KEY=VALUE")
    s.add_argument("--offline", action="store_true", help="create keys only; register later")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("register", help="register an identity created with --offline")
    s.add_argument("name"); s.set_defaults(fn=cmd_register)

    s = sub.add_parser("show", help="show a local identity"); s.add_argument("name"); s.set_defaults(fn=cmd_show)

    s = sub.add_parser("resolve", help="resolve a DID to its DID document")
    s.add_argument("did"); s.add_argument("--verify", action="store_true", help="replay the full log locally")
    s.set_defaults(fn=cmd_resolve)

    s = sub.add_parser("log", help="print a DID's key event log"); s.add_argument("did"); s.set_defaults(fn=cmd_log)

    s = sub.add_parser("rotate", help="rotate to the pre-committed key"); s.add_argument("name"); s.set_defaults(fn=cmd_rotate)

    s = sub.add_parser("deactivate", help="permanently deactivate an identity")
    s.add_argument("target", help="local name (self-deactivation) or DID (with --as)")
    s.add_argument("--as", dest="as_controller", metavar="CONTROLLER", help="deactivate as this controller")
    s.set_defaults(fn=cmd_deactivate)

    s = sub.add_parser("agents", help="list agents owned by a controller")
    s.add_argument("controller", help="local name or DID"); s.set_defaults(fn=cmd_agents)

    s = sub.add_parser("whoami", help="make an authenticated call to the registry"); s.add_argument("name"); s.set_defaults(fn=cmd_whoami)

    s = sub.add_parser("sign", help="print an Authorization header (e.g. for curl)")
    s.add_argument("name"); s.add_argument("method"); s.add_argument("url"); s.add_argument("--data")
    s.add_argument("--grant", help="grant chain (file or token) to present; prints both headers")
    s.set_defaults(fn=cmd_sign)

    s = sub.add_parser("grant", help="issue (or delegate) a capability grant; prints the chain")
    s.add_argument("issuer", help="local name of the issuing identity")
    s.add_argument("subject", help="DID or local name of the agent receiving authority")
    s.add_argument("--scope", action="append", required=True, help="e.g. tools.search, files.* (repeatable)")
    s.add_argument("--aud", action="append", required=True, help="host[:port] the grant is valid at (repeatable)")
    s.add_argument("--ttl", type=int, default=900, help="seconds (default 900, max 86400)")
    s.add_argument("--depth", type=int, default=0, help="how many more times the subject may delegate")
    s.add_argument("--parent", help="chain (file or token) issued to ISSUER, to delegate from")
    lg = s.add_argument_group("limits (all optional; delegations inherit and may only tighten)")
    lg.add_argument("--resource", action="append", help="resource pattern, exact or ending in * (repeatable)")
    lg.add_argument("--per-call", type=int, help="max amount per call, in --unit")
    lg.add_argument("--budget", type=int, help="max total amount across all calls, in --unit")
    lg.add_argument("--unit", default=None, help="spend unit (default USD-cents)")
    lg.add_argument("--rate", help="max calls per window, e.g. 10/60 (10 per 60 s)")
    lg.add_argument("--uses", type=int, help="max total number of calls")
    s.add_argument("-o", "--out", help="write the chain to this file")
    s.set_defaults(fn=cmd_grant)

    s = sub.add_parser("inspect", help="decode a grant chain (file or token)")
    s.add_argument("chain"); s.set_defaults(fn=cmd_inspect)

    s = sub.add_parser("revoke", help="revoke a grant you issued (cascades to its delegations)",
                       epilog="A grant id that starts with '-' must follow '--': agentauth revoke ISSUER -- -abc123")
    s.add_argument("issuer")
    s.add_argument("grant_id", help="id of the grant to revoke (see `agentauth inspect`)")
    s.set_defaults(fn=cmd_revoke)

    s = sub.add_parser("serve", help="run the registry")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--db", default=None, help="database URL or SQLite path (env AGENTAUTH_DATABASE_URL; default agentauth.db)")
    s.add_argument("--audience", action="append", help="extra host[:port] the registry answers to")
    s.add_argument("--workers", type=int, default=1, help="worker processes (use Redis for >1; see docs/operations.md)")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("db", help="registry database maintenance")
    s.add_argument("action", choices=["migrate", "status", "verify"],
                   help="migrate: apply schema migrations; status: show versions; verify: replay every log")
    s.add_argument("--database-url", default=None, help="defaults to AGENTAUTH_DATABASE_URL / AGENTAUTH_DB")
    s.set_defaults(fn=cmd_db)

    s = sub.add_parser("sync", help="copy a DID's events to every registry in --registry that lacks them")
    s.add_argument("did"); s.set_defaults(fn=cmd_sync)

    s = sub.add_parser("audit", help="verify a service's audit log")
    s.add_argument("path", help="SQLite file written by agentauth.audit.AuditLog")
    s.add_argument("--key", help="multikey every entry must be signed with")
    s.add_argument("--head", help="exported head SEQ:DIGEST that must still be present")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("version", help="print the version"); s.set_defaults(fn=cmd_version)
    return p


def make_registry(spec: str):
    urls = [u.strip() for u in spec.split(",") if u.strip()]
    if len(urls) == 1:
        return RegistryClient(urls[0])
    return RegistryPool([RegistryClient(u) for u in urls])


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    reg = make_registry(args.registry)
    try:
        args.fn(args, reg)
    except RegistryError as e:
        sys.exit(f"registry error {e.status}: {e.detail}")
    except (GrantError, LimitError) as e:
        sys.exit(f"grant error: {e}")
    except EquivocationError as e:
        sys.exit(f"registry equivocation detected: {e}")
    except httpx.TransportError as e:
        sys.exit(f"error: cannot reach the registry ({e})")
    except (ValueError, RuntimeError, OSError) as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
