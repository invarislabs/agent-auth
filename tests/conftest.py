import os
import uuid

import pytest
from fastapi.testclient import TestClient

from agentauth import AgentIdentity, RegistryClient
from agentauth.config import Settings
from agentauth.server import create_app

REDIS_URL = os.environ.get("AGENTAUTH_TEST_REDIS_URL")
POSTGRES_URL = os.environ.get("AGENTAUTH_TEST_POSTGRES_URL")


def registry_settings(**kw) -> Settings:
    """Registry settings for tests: no rate limits unless a test asks for them."""
    s = Settings(audiences={"testserver"}, rate_limit_writes=None, rate_limit_reads=None, log_format="text")
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def make_registry(db_path=":memory:", **kw):
    app = create_app(db_path=db_path, settings=registry_settings(**kw))
    http = TestClient(app)
    return RegistryClient("http://testserver", client=http), http


@pytest.fixture
def registry(tmp_path):
    return make_registry(str(tmp_path / "reg.db"))


def new_agent(reg, **kw):
    ident, event = AgentIdentity.create(**kw)
    reg.register(event)
    return ident


@pytest.fixture
def redis_url():
    if not REDIS_URL:
        pytest.skip("set AGENTAUTH_TEST_REDIS_URL to run Redis tests")
    import redis

    r = redis.Redis.from_url(REDIS_URL)
    r.flushdb()
    yield REDIS_URL
    r.flushdb()


@pytest.fixture
def postgres_url():
    if not POSTGRES_URL:
        pytest.skip("set AGENTAUTH_TEST_POSTGRES_URL to run PostgreSQL tests")
    import psycopg

    schema = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
    sep = "&" if "?" in POSTGRES_URL else "?"
    yield f"{POSTGRES_URL}{sep}options=-csearch_path%3D{schema}"
    with psycopg.connect(POSTGRES_URL, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA {schema} CASCADE")
