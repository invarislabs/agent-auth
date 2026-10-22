"""End to end with real processes: `agentauth serve`, the CLI, and the example tool service over TCP."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from agentauth import AgentIdentity, GrantChain, RegistryClient

pytestmark = pytest.mark.e2e
ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_ready(url: str, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except httpx.TransportError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{url} did not become ready")


@pytest.fixture
def env(tmp_path):
    e = {k: v for k, v in os.environ.items() if not k.startswith("AGENTAUTH_")}
    e.update(AGENTAUTH_HOME=str(tmp_path / "keys"), AGENTAUTH_PASSPHRASE="correct horse battery staple",
             AGENTAUTH_LOG_FORMAT="json", PYTHONWARNINGS="ignore")
    return e


@pytest.fixture
def procs():
    started = []
    yield started
    for p in started:
        p.terminate()
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


def start(procs, args, env, log):
    p = subprocess.Popen(args, env=env, stdout=open(log, "w"), stderr=subprocess.STDOUT, cwd=ROOT)
    procs.append(p)
    return p


def cli(env, registry, *args, check=True):
    r = subprocess.run([sys.executable, "-m", "agentauth.cli", "--registry", registry, *args],
                       env=env, capture_output=True, text=True, timeout=60, cwd=ROOT)
    if check and r.returncode != 0:
        raise AssertionError(f"agentauth {' '.join(args)} failed: {r.stderr}")
    return r


def test_cli_registry_and_tool_service(tmp_path, env, procs):
    port, svc_port = free_port(), free_port()
    registry = f"http://127.0.0.1:{port}"
    start(procs, [sys.executable, "-m", "agentauth.cli", "serve", "--port", str(port),
                  "--db", str(tmp_path / "reg.db")], env, tmp_path / "registry.log")
    wait_ready(f"{registry}/readyz")

    human = json.loads(cli(env, registry, "init", "arunima", "--meta", "kind=human").stdout)
    cli(env, registry, "init", "researcher", "--controller", "arunima")
    cli(env, registry, "init", "summarizer", "--controller", "researcher")
    assert json.loads(cli(env, registry, "whoami", "researcher").stdout)["kid"].endswith("#key-0")
    rot = json.loads(cli(env, registry, "rotate", "researcher").stdout)
    assert rot["new_kid"].endswith("#key-1") and not rot["resumed_unfinished_rotation"]
    assert json.loads(cli(env, registry, "whoami", "researcher").stdout)["kid"].endswith("#key-1")
    resolved = json.loads(cli(env, registry, "resolve", rot["did"], "--verify").stdout)
    assert resolved["didDocumentMetadata"]["versionId"] == "1"

    start(procs, [sys.executable, "examples/tool_service.py", "--registry", registry, "--trust", human["did"],
                  "--port", str(svc_port), "--audit", str(tmp_path / "audit.db")], env, tmp_path / "svc.log")
    svc = f"http://127.0.0.1:{svc_port}"
    wait_ready(f"{svc}/healthz")

    aud = f"127.0.0.1:{svc_port}"
    cli(env, registry, "grant", "arunima", "researcher", "--scope", "tools.*", "--aud", aud, "--depth", "1",
        "-o", str(tmp_path / "researcher.grant"))
    cli(env, registry, "grant", "researcher", "summarizer", "--scope", "tools.search", "--aud", aud,
        "--parent", str(tmp_path / "researcher.grant"), "-o", str(tmp_path / "summarizer.grant"))
    chain = GrantChain.decode((tmp_path / "summarizer.grant").read_text().strip())
    assert len(chain.links) == 2

    summarizer = AgentIdentity.load(tmp_path / "keys", "summarizer", passphrase=env["AGENTAUTH_PASSPHRASE"])
    r = httpx.post(f"{svc}/search", json={"q": "hi"}, auth=summarizer.httpx_auth(chain))
    assert r.status_code == 200, r.text
    assert r.json()["chain"][0] == human["did"]

    # replaying the exact same signed request over the wire is refused
    body = b'{"q":"hi"}'
    headers = {**summarizer.headers("POST", f"{svc}/search", body, chain), "content-type": "application/json"}
    assert httpx.post(f"{svc}/search", content=body, headers=headers).status_code == 200
    assert httpx.post(f"{svc}/search", content=body, headers=headers).status_code == 401

    # the CLI's sign command produces headers curl could use
    out = cli(env, registry, "sign", "summarizer", "POST", f"{svc}/search", "--data", '{"q":"cli"}',
              "--grant", str(tmp_path / "summarizer.grant")).stdout.splitlines()
    h = dict(line.split(": ", 1) for line in out)
    r = httpx.post(f"{svc}/search", content=b'{"q":"cli"}', headers={**h, "content-type": "application/json"})
    assert r.status_code == 200, r.text

    cli(env, registry, "revoke", "arunima", chain.root.id)
    time.sleep(5.5)  # the example caches "not revoked" for 5 s
    r = httpx.post(f"{svc}/search", json={"q": "after"}, auth=summarizer.httpx_auth(chain))
    assert r.status_code == 403 and "revoked" in r.json()["detail"]

    # kill switch
    target = json.loads(cli(env, registry, "show", "summarizer").stdout)["did"]
    cli(env, registry, "deactivate", target, "--as", "researcher")
    assert cli(env, registry, "whoami", "summarizer", check=False).returncode != 0

    # operational endpoints and tooling on the real server
    assert "agentauth_registry_events_total" in httpx.get(f"{registry}/metrics").text
    assert json.loads(cli(env, registry, "audit", str(tmp_path / "audit.db")).stdout)["ok"] is True
    log_lines = [json.loads(line) for line in (tmp_path / "registry.log").read_text().splitlines()
                 if line.startswith("{")]
    assert any(line.get("msg") == "identity registered" for line in log_lines)
    assert not any("correct horse" in line for line in (tmp_path / "registry.log").read_text().splitlines())


def test_multi_worker_registry_with_redis_and_postgres(tmp_path, env, procs):
    redis_url = os.environ.get("AGENTAUTH_TEST_REDIS_URL")
    pg_url = os.environ.get("AGENTAUTH_TEST_POSTGRES_URL")
    if not (redis_url and pg_url):
        pytest.skip("needs AGENTAUTH_TEST_REDIS_URL and AGENTAUTH_TEST_POSTGRES_URL")
    import psycopg

    schema = f"e2e_{os.getpid()}"
    with psycopg.connect(pg_url, autocommit=True) as c:
        c.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        c.execute(f"CREATE SCHEMA {schema}")
    sep = "&" if "?" in pg_url else "?"
    port = free_port()
    e = dict(env, AGENTAUTH_DATABASE_URL=f"{pg_url}{sep}options=-csearch_path%3D{schema}",
             AGENTAUTH_REDIS_URL=redis_url, AGENTAUTH_AUDIENCES=f"127.0.0.1:{port}")
    start(procs, [sys.executable, "-m", "agentauth.cli", "serve", "--port", str(port), "--workers", "3"], e,
          tmp_path / "registry.log")
    registry = f"http://127.0.0.1:{port}"
    wait_ready(f"{registry}/readyz")
    assert httpx.get(f"{registry}/readyz").json()["checks"] == {"database": "ok", "redis": "ok"}

    reg = RegistryClient(registry)
    agent, ev = AgentIdentity.create(name="mw")
    reg.register(ev)
    auth = agent.authorization("GET", f"{registry}/v1/whoami")
    codes = []
    for _ in range(12):  # new connection each time: requests spread over the workers
        codes.append(httpx.get(f"{registry}/v1/whoami", headers={"Authorization": auth, "Connection": "close"}).status_code)
    assert codes[0] == 200 and codes[1:] == [401] * 11  # replay refused by every worker
    for _ in range(5):
        reg.rotate(agent)
    assert reg.verified_state(agent.did).seq == 5
    with psycopg.connect(pg_url, autocommit=True) as c:
        c.execute(f"DROP SCHEMA {schema} CASCADE")
