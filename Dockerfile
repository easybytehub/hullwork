# syntax=docker/dockerfile:1

# --- build: resolve dependencies into a self-contained virtualenv -------------
#
# **Pinned by digest, not by tag** (OpenSSF Scorecard, Pinned-Dependencies). `python:3.12-slim` is a
# pointer somebody else moves: two builds of the same commit can differ, which makes a reproducible
# build a coincidence. The digest is the manifest list, so buildx still picks amd64 or arm64 by
# itself. Dependabot proposes the bump; a human takes it.
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY pyproject.toml README.md LICENSE.md ./
COPY hullwork ./hullwork

# Nothing optional is installed unless you ask for it, so the default image carries no error
# reporting SDK and no Postgres driver. Add them at build time when you want them:
#   docker build --build-arg EXTRAS='[postgres,telemetry]' .
ARG EXTRAS=
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install ".${EXTRAS}"

# --- runtime: no build tools, no source tree, no root ------------------------
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    HULLWORK_DATABASE_URL="sqlite:////data/hullwork.db"

# **Where this build reports its own crashes, and nowhere else** (item 152). Empty here and empty in
# every build made from a checkout: the repository contains no destination, which is a fact anybody
# can check with `grep` rather than a promise about our intentions. The release workflow passes one
# from a repository secret, so the image *we publish* reports the defects it hits on other people's
# machines — a Sentry DSN is a public write-only key, so finding it in the image is expected.
#
# What travels is not an event: `hullwork/upstream.py` constructs it from an enumerated set of
# fields and cannot carry a message, a local, a URL or a hostname. `HULLWORK_TELEMETRY=off` declines.
ARG UPSTREAM_DSN=
ENV HULLWORK_UPSTREAM_DSN="${UPSTREAM_DSN}"

# `git` and the Docker CLI, for the dispatcher (item 082). The receiver needs neither; they are here
# because both programs run from this one image, and the alternative — a second image differing by two
# packages — is a second thing to keep in step. The socket is not in the image: it is mounted only
# into the dispatcher service, so the receiver cannot reach the daemon even though it could speak to
# it. `docker-cli` alone, never the daemon.
RUN apt-get update \
 && apt-get install --no-install-recommends -y git ca-certificates curl gnupg \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && chmod a+r /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install --no-install-recommends -y docker-ce-cli \
 && apt-get purge -y gnupg \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 hullwork

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
# Migrations ship in the image. Without them the container starts, answers /health, and then fails
# on the first webhook because no tables exist — a service that looks healthy and is not.
COPY --chown=hullwork:hullwork alembic.ini ./
COPY --chown=hullwork:hullwork migrations ./migrations
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The database lives on a volume. A container that loses its data on restart is not persistence,
# and SQLite writing inside the layer looks like it works right up until the first `docker compose up`
# after a rebuild.
RUN mkdir -p /data && chown hullwork:hullwork /data
VOLUME ["/data"]

USER hullwork
EXPOSE 8000

# python, not curl: the slim image has no curl and adding one would be a dependency for a probe.
#
# `/ready`, not `/health`: a probe that cannot fail tells a container manager nothing. This one
# returns 503 for an unreachable forge, an unwritable database, a stopped retry clock, a backlog
# nobody is draining, or an error-reporting SDK that was configured and is inert — every one of
# which used to look exactly like a healthy container.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request as r; r.urlopen('http://127.0.0.1:8000/ready').read()"]

ENTRYPOINT ["docker-entrypoint.sh"]
# `--no-access-log` is not a preference. The webhook token is a path segment, so the access log
# writes a live credential to disk on every single delivery — found by reading our own container's
# logs after pointing Hullwork at itself. Anyone overriding this command must keep the flag.
CMD ["uvicorn", "hullwork.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
