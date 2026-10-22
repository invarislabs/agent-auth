"""The `agentauth` CLI, run in-process against an in-memory registry."""

import json

import pytest
from conftest import make_registry

from agentauth import cli
from agentauth.grants import GrantChain


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    reg, http = make_registry(str(tmp_path / "reg.db"))
    monkeypatch.setattr(cli, "make_registry", lambda spec: reg)
    monkeypatch.setenv("AGENTAUTH_PASSPHRASE", "a test passphrase")
    home = str(tmp_path / "keys")

    def go(*argv, expect_exit=None):
        capsys.readouterr()
        if expect_exit is not None:
            with pytest.raises(SystemExit) as e:
                cli.main(["--dir", home, *argv])
            out = capsys.readouterr()
            return e.value.code, out.out + out.err
        cli.main(["--dir", home, *argv])
        out = capsys.readouterr().out
        try:
            return json.loads(out)
        except ValueError:
            return out

    go.reg, go.tmp = reg, tmp_path
    return go


def test_identity_lifecycle(run):
    human = run("init", "arunima", "--meta", "kind=human")
    agent = run("init", "researcher", "--controller", "arunima")
    assert run("show", "researcher")["controller"] == human["did"]
    assert run("whoami", "researcher")["kid"].endswith("#key-0")
    rot = run("rotate", "researcher")
    assert rot["new_kid"].endswith("#key-1")
    assert run("resolve", agent["did"], "--verify")["verified"]
    assert len(run("log", agent["did"])) == 2
    assert run("agents", "arunima")[0]["did"] == agent["did"]
    run("deactivate", agent["did"], "--as", "arunima")
    assert run("resolve", agent["did"])["didDocumentMetadata"]["deactivated"] is True
    code, msg = run("init", "arunima", expect_exit=True)
    assert "already exists" in str(code)


def test_offline_init_then_register(run):
    out = run("init", "later", "--offline")
    assert out["registered"] is False
    assert run("register", "later")["didDocument"]["id"] == out["did"]


def test_self_deactivation(run):
    run("init", "solo")
    assert run("deactivate", "solo")["active"] is False
    code, msg = run("whoami", "solo", expect_exit=True)
    assert "deactivated" in str(code)


def test_grants_limits_sign_revoke(run, capsys):
    run("init", "boss")
    run("init", "worker")
    run("init", "helper")
    t = run.tmp
    run("grant", "boss", "worker", "--scope", "payments.*", "--aud", "svc.example", "--depth", "1",
        "--budget", "5000", "--per-call", "2000", "--rate", "10/60", "--uses", "50", "-o", str(t / "w.grant"))
    run("grant", "worker", "helper", "--scope", "payments.buy", "--aud", "svc.example", "--budget", "3000",
        "--parent", str(t / "w.grant"), "-o", str(t / "h.grant"))
    links = run("inspect", str(t / "h.grant"))
    assert len(links) == 2 and links[1]["limits"]["spend"]["total"] == 3000
    code, msg = run("grant", "worker", "helper", "--scope", "payments.buy", "--aud", "svc.example",
                    "--budget", "9000", "--parent", str(t / "w.grant"), expect_exit=True)
    assert "exceed" in str(code)
    code, msg = run("grant", "boss", "worker", "--scope", "x", "--aud", "svc", "--rate", "fast", expect_exit=True)
    assert "COUNT/SECONDS" in str(code)

    out = run("sign", "helper", "POST", "http://svc.example/buy", "--data", "{}", "--grant", str(t / "h.grant"))
    assert out.startswith("Authorization: AgentSig ") and "\nAgentGrant: " in out
    assert run("sign", "helper", "GET", "http://svc.example/x").startswith("AgentSig ")

    chain = GrantChain.decode((t / "w.grant").read_text().strip())
    assert run("revoke", "boss", chain.leaf.id)["new"] is True
    assert run.reg.revoked([(chain.root.iss, chain.root.id)])


def test_db_and_audit_commands(run, tmp_path):
    from agentauth import AuditLog

    db = f"sqlite:///{tmp_path}/fresh.db"
    assert run("db", "status", "--database-url", db)["schema_version"] == 0
    assert run("db", "migrate", "--database-url", db)["applied"] == [1, 2]
    assert run("db", "verify", "--database-url", db)["ok"] is True
    code, _ = run("db", "verify", "--database-url", f"sqlite:///{tmp_path}/other.db", expect_exit=True)
    assert "migrate" in str(code)

    log = AuditLog(str(tmp_path / "audit.db"))
    log.record(agent="did:agent:a", outcome="allowed", status=200)
    head = log.head()
    assert run("audit", str(tmp_path / "audit.db"), "--head", f"{head[0]}:{head[1]}")["ok"] is True
    code, _ = run("audit", str(tmp_path / "audit.db"), "--head", "0:zWrong", expect_exit=True)
    assert code == 1
    assert run("version")["agentauth"]


def test_sync_requires_pool(run):
    code, _ = run("sync", "did:agent:" + "1" * 45, expect_exit=True)
    assert "several registries" in str(code)


def test_make_registry_builds_pool():
    from agentauth import RegistryClient, RegistryPool

    assert isinstance(cli.make_registry("http://a"), RegistryClient)
    pool = cli.make_registry("http://a, http://b")
    assert isinstance(pool, RegistryPool) and len(pool.registries) == 2


def test_unreachable_registry_is_a_clean_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AGENTAUTH_PASSPHRASE", "pw-pw-pw-pw")
    with pytest.raises(SystemExit) as e:
        cli.main(["--registry", "http://127.0.0.1:1", "--dir", str(tmp_path), "init", "x"])
    assert "cannot reach the registry" in str(e.value.code)


def test_unencrypted_keys_warn(run, monkeypatch, capsys):
    monkeypatch.delenv("AGENTAUTH_PASSPHRASE")
    capsys.readouterr()
    cli.main(["--dir", str(run.tmp / "plain"), "init", "plain"])
    assert "unencrypted" in capsys.readouterr().err


def test_serve_refuses_multiple_workers_without_redis(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_REDIS_URL", raising=False)
    with pytest.raises(SystemExit) as e:
        cli.main(["serve", "--workers", "2", "--db", ":memory:"])
    assert "AGENTAUTH_REDIS_URL" in str(e.value.code)


@pytest.mark.redis
def test_redis_rate_limiter(redis_url):
    import redis

    from agentauth.ratelimit import RedisRateLimiter

    rl = RedisRateLimiter(redis.Redis.from_url(redis_url))
    assert [rl.hit("ip", 2, 60)[0] for _ in range(3)] == [True, True, False]
    down = RedisRateLimiter(redis.Redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.2))
    assert down.hit("ip", 1, 60) == (True, 0)  # availability control: lets traffic through when Redis is down


def test_memory_rate_limiter_is_bounded():
    from agentauth.ratelimit import MemoryRateLimiter

    rl = MemoryRateLimiter(max_keys=10)
    for i in range(100):
        rl.hit(f"k{i}", 5, 60)
    assert len(rl._windows) <= 10
