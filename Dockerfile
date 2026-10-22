# AgentAuth registry image.
#
#   docker build -t agentauth-registry .
#   docker run -p 8000:8000 -e AGENTAUTH_AUDIENCES=localhost:8000 -v agentauth-data:/data agentauth-registry
#
# Dependencies are installed from deploy/requirements.lock with hash checking,
# so a rebuild of the same commit installs exactly the same packages.
# For fully reproducible builds also pin the base image by digest
# (python:3.12-slim-bookworm@sha256:...); Dependabot keeps it current.

FROM python:3.12-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY deploy/requirements.lock deploy/requirements.lock
RUN python -m venv /opt/agentauth \
 && /opt/agentauth/bin/pip install --require-hashes -r deploy/requirements.lock
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY agentauth ./agentauth
RUN /opt/agentauth/bin/pip install --no-deps .

FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.title="AgentAuth registry" \
      org.opencontainers.image.source="https://github.com/invarislabs/agent-auth" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 agentauth \
 && useradd --system --uid 10001 --gid agentauth --home-dir /data --shell /usr/sbin/nologin agentauth \
 && mkdir -p /data && chown agentauth:agentauth /data
COPY --from=build /opt/agentauth /opt/agentauth
ENV PATH=/opt/agentauth/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AGENTAUTH_DATABASE_URL=sqlite:////data/agentauth.db \
    AGENTAUTH_LOG_FORMAT=json
USER agentauth
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["agentauth"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
