"""Registry operations: configuration, limits, health, metrics, storage and migrations."""

import json
import sqlite3

import pytest
from conftest import make_registry, new_agent, registry_settings
from fastapi.testclient import TestClient

from agentauth import AgentIdentity, RegistryClient, RegistryError
from agentauth.config import ConfigError, Settings, parse_rate
from agentauth.server import create_app
from agentauth.store import SCHEMA_VERSION, SchemaError, Store, open_store

# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #


def test_settings_from_env(tmp_path):
    secret = tmp_path / "tok"
    secret.write_text("s" * 32 + "\n")
    s = Settings.from_env({
        "AGENTAUTH_DATABASE_URL": "postgresql://u:hunter2@db/agentauth",
        "AGENTAUTH_AUDIENCES": "Registry.Example.com, 10.0.0.1:8000",
        "AGENTAUTH_RATE_LIMIT_WRITES": "10/60",
        "AGENTAUTH_RATE_LIMIT_READS": "off",
        "AGENTAUTH_REGISTRATION_TOKEN_FILE": str(secret),
        "AGENTAUTH_TRUSTED_PROXY_HOPS": "1",
    })
    assert s.audiences == {"registry.example.com", "10.0.0.1:8000"}
    assert s.rate_limit_writes == (10, 60) and s.rate_limit_reads is None
    assert s.registration_token == "s" * 32
    d = s.describe()
    assert "hunter2" not in json.dumps(d) and d["registration"] == "token"


def test_legacy_db_variable_still_works():
    assert Settings.from_env({"AGENTAUTH_DB": "/var/lib/a.db"}).database_url == "/var/lib/a.db"


@pytest.mark.parametrize("env", [
    {"AGENTAUTH_AUDIENCES": ""},
    {"AGENTAUTH_AUDIENCES": "https://registry.example.com"},
    {"AGENTAUTH_RATE_LIMIT_WRITES": "lots"},
    {"AGENTAUTH_MAX_BODY_BYTES": "10"},
    {"AGENTAUTH_AUTO_MIGRATE": "maybe"},
    {"AGENTAUTH_REGISTRATION_TOKEN": "short"},
    {"AGENTAUTH_REDIS_URL": "http://x"},
    {"AGENTAUTH_LOG_LEVEL": "CHATTY"},
])
def test_invalid_settings_refused(env):
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_parse_rate():
    assert parse_rate("5/10s", "x") == (5, 10) and parse_rate("0", "x") is None
    with pytest.raises(ConfigError):
        parse_rate("0/10", "x")


# --------------------------------------------------------------------------- #
# operational endpoints
# --------------------------------------------------------------------------- #


def test_health_ready_info_metrics(registry):
    reg, http = registry
    new_agent(reg, name="m")
    assert http.get("/healthz").json() == {"ok": True}
    r = http.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": "ok"}
    info = http.get("/v1/info").json()
    assert info["schema_version"] == SCHEMA_VERSION and info["protocols"]["grant"] == "agentauth-grant/1"
    m = http.get("/metrics").text
    assert 'agentauth_registry_events_total{type="inception",outcome="accepted"} 1' in m
    assert "agentauth_http_request_duration_seconds_bucket" in m
    assert "agentauth_registry_identities 1.0" in m


def test_readyz_reports_broken_database(registry):
    reg, http = registry
    http.app.state.store.close()
    r = http.get("/readyz")
    assert r.status_code == 503 and r.json()["ok"] is False


def test_request_id_propagates(registry):
    _, http = registry
    assert http.get("/healthz", headers={"X-Request-ID": "abc-123"}).headers["x-request-id"] == "abc-123"
    assert len(http.get("/healthz", headers={"X-Request-ID": "bad id!"}).headers["x-request-id"]) == 32


def test_metrics_can_be_disabled():
    _, http = make_registry(metrics_enabled=False)
    assert http.get("/metrics").status_code == 404


def test_unknown_errors_are_json_500(registry):
    reg, http = registry

    def boom(did):
        raise RuntimeError("disk on fire")

    http.app.state.store.get_state = boom
    c = TestClient(http.app, raise_server_exceptions=False)
    r = c.get("/v1/identities/did:agent:" + "1" * 45)
    assert r.status_code == 500 and r.json()["detail"] == "internal error" and "request_id" in r.json()


# --------------------------------------------------------------------------- #
# input limits and validation
# --------------------------------------------------------------------------- #


def test_oversized_bodies_refused_before_reading():
    _, http = make_registry(max_body_bytes=2048)
    r = http.post("/v1/identities", content=b"x" * 5000, headers={"content-type": "application/json"})
    assert r.status_code == 413

    def chunks():
        for _ in range(10):
            yield b"x" * 1000

    r = http.post("/v1/identities", content=chunks(), headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_strict_json(registry):
    _, http = registry
    for raw in (b'{"body":{},"body":{}}', b'{"body":NaN}', b'{"body":Infinity}'):
        r = http.post("/v1/identities", content=raw, headers={"content-type": "application/json"})
        assert r.status_code == 400


@pytest.mark.parametrize("did", ["did:agent:x", "not-a-did", "did:agent:" + "0" * 45, "did:agent:" + "1" * 45 + "/../x"])
def test_malformed_dids_in_paths(registry, did):
    _, http = registry
    assert http.get(f"/v1/identities/{did}").status_code == 404


def test_client_refuses_to_build_paths_from_bad_dids(registry):
    reg, _ = registry
    with pytest.raises(ValueError):
        reg.resolve("did:agent:x/../../v1/revocations")


@pytest.mark.parametrize("body", [
    {}, {"grants": "x"}, {"grants": [["a"]]}, {"grants": [[1, 2]]}, {"grants": [["a", "b"]] * 33},
    {"grants": [["a", "x" * 200]]}, [],
])
def test_revocation_check_validation(registry, body):
    _, http = registry
    assert http.post("/v1/revocations/check", json=body).status_code == 400


def test_pagination(registry):
    reg, http = registry
    owner = new_agent(reg, name="owner")
    kids = sorted(new_agent(reg, name=f"k{i}", controller=owner).did for i in range(5))
    page = http.get(f"/v1/identities/{owner.did}/agents", params={"limit": 2}).json()
    assert [a["did"] for a in page["agents"]] == kids[:2] and page["next"] == kids[1]
    assert [a["did"] for a in reg.controlled_agents(owner.did)] == kids  # client follows pages
    everything = http.get("/v1/identities", params={"limit": 1000}).json()
    assert len(everything["identities"]) == 6 and everything["next"] is None
    assert http.get("/v1/identities", params={"limit": 0}).status_code == 400


# --------------------------------------------------------------------------- #
# rate limits and registration control
# --------------------------------------------------------------------------- #


def test_write_rate_limit():
    reg, http = make_registry(rate_limit_writes=(3, 60))
    for i in range(3):
        new_agent(reg, name=f"a{i}")
    with pytest.raises(RegistryError) as e:
        new_agent(reg, name="too-many")
    assert e.value.status == 429
    r = http.post("/v1/identities", json={})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert http.get("/healthz").status_code == 200  # ops endpoints are never limited


def test_rate_limit_uses_forwarded_address_only_when_trusted():
    _, http = make_registry(rate_limit_reads=(2, 60), trusted_proxy_hops=1)
    did = "did:agent:" + "1" * 45
    for ip in ("1.1.1.1", "2.2.2.2"):
        for _ in range(2):
            assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": ip}).status_code == 404
    assert http.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429
    _, untrusted = make_registry(rate_limit_reads=(2, 60))
    for ip in ("1.1.1.1", "2.2.2.2"):
        untrusted.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": ip})
    assert untrusted.get(f"/v1/identities/{did}", headers={"X-Forwarded-For": "3.3.3.3"}).status_code == 429


def test_registration_token():
    token = "t" * 32
    _, http = make_registry(registration_token=token)
    ident, ev = AgentIdentity.create(name="gated")
    assert http.post("/v1/identities", json=ev).status_code == 401
    assert http.post("/v1/identities", json=ev, headers={"X-AgentAuth-Registration-Token": "x" * 32}).status_code == 401
    reg = RegistryClient("http://testserver", client=http, registration_token=token)
    reg.register(ev)
    assert reg.resolve(ident.did)["didDocument"]["id"] == ident.did
    # Only registration is gated; key events stay open (they're signed by the identity itself).
    reg.rotate(ident)


# --------------------------------------------------------------------------- #
# storage and migrations
# --------------------------------------------------------------------------- #

_V03_SCHEMA = """
CREATE TABLE identities (did TEXT PRIMARY KEY, controller TEXT, active INTEGER NOT NULL, state TEXT NOT NULL, updated TEXT NOT NULL);
CREATE INDEX identities_controller ON identities(controller);
CREATE TABLE events (did TEXT NOT NULL, seq INTEGER NOT NULL, digest TEXT NOT NULL, event TEXT NOT NULL, PRIMARY KEY (did, seq));
CREATE TABLE revocations (issuer TEXT NOT NULL, grant_id TEXT NOT NULL, revoked_at INTEGER NOT NULL, event TEXT NOT NULL, PRIMARY KEY (issuer, grant_id));
"""


def test_upgrade_from_v03_database(tmp_path):
    import dataclasses

    from agentauth.identity import event_digest

    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.executescript(_V03_SCHEMA)
    ident, ev = AgentIdentity.create(name="legacy")
    db.execute("INSERT INTO events VALUES (?,?,?,?)", (ident.did, 0, event_digest(ev), json.dumps(ev)))
    db.execute("INSERT INTO identities VALUES (?,?,?,?,?)",
               (ident.did, None, 1, json.dumps(dataclasses.asdict(ident.state)), ident.state.updated))
    db.commit()
    db.close()

    with pytest.raises(SchemaError, match="migrate"):
        Store(path, auto_migrate=False)
    store = Store(path)  # auto-migrates
    assert store.schema_version() == SCHEMA_VERSION and store.verify_integrity() == []
    reg = RegistryClient("http://testserver", client=TestClient(create_app(settings=registry_settings(), store=store)))
    assert reg.verified_state(ident.did).did == ident.did
    reg.rotate(ident)


def test_newer_schema_refused(tmp_path):
    path = str(tmp_path / "future.db")
    s = Store(path)
    s._q("INSERT INTO schema_migrations VALUES (99, 'from the future', 'x')")
    s.close()
    with pytest.raises(SchemaError, match="newer"):
        Store(path)


def test_integrity_check_detects_tampering(tmp_path):
    path = str(tmp_path / "t.db")
    reg, http = make_registry(path)
    agent = new_agent(reg, name="victim")
    reg.rotate(agent)
    db = sqlite3.connect(path)
    row = db.execute("SELECT event FROM events WHERE seq=1").fetchone()
    ev = json.loads(row[0])
    ev["body"]["ts"] = "2001-01-01T00:00:00Z"
    db.execute("UPDATE events SET event=? WHERE seq=1", (json.dumps(ev),))
    db.commit()
    problems = open_store(path).verify_integrity()
    assert len(problems) == 1 and agent.did in problems[0]


@pytest.mark.parametrize("url,expected", [
    ("sqlite:///:memory:", ":memory:"), ("sqlite:///rel.db", "rel.db"), ("sqlite:////abs/x.db", "/abs/x.db"),
])
def test_sqlite_urls(url, expected, monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, path, **kw):
            seen["path"] = path

    monkeypatch.setattr("agentauth.store.Store", Fake)
    open_store(url)
    assert seen["path"] == expected


@pytest.mark.postgres
def test_full_flow_on_postgres(postgres_url):
    from agentauth.store import PostgresStore

    store = PostgresStore(postgres_url)
    assert store.schema_version() == SCHEMA_VERSION
    app = create_app(settings=registry_settings(), store=store)
    reg = RegistryClient("http://testserver", client=TestClient(app))
    owner = new_agent(reg, name="pg-owner")
    agent = new_agent(reg, name="pg-agent", controller=owner)
    reg.rotate(agent)
    g = owner.grant(agent.did, ["x.y"], ["svc"])
    assert reg.revoke_grant(owner, g.leaf.id)["new"] is True
    assert reg.revoke_grant(owner, g.leaf.id)["new"] is False
    assert reg.revoked([(owner.did, g.leaf.id)]) == {(owner.did, g.leaf.id)}
    reg.deactivate_controlled(owner, agent.did)
    assert reg.controlled_agents(owner.did) == [{"did": agent.did, "active": False}]
    assert store.verify_integrity() == [] and store.stats()["identities"] == 2
    assert TestClient(app).get("/readyz").json()["checks"]["database"] == "ok"
    # migrating again is a no-op, even from a second "replica"
    assert PostgresStore(postgres_url).migrate() == []
    store.close()
