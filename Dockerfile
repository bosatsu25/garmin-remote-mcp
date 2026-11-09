# syntax=docker/dockerfile:1
# Tip: pin the base image by digest (python:3.13-slim@sha256:...) and let Dependabot bump it.
FROM python:3.13-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
# 1) Every third-party wheel is verified against requirements.lock hashes.
COPY requirements.lock ./
RUN pip install --require-hashes --only-binary=:all: --prefix=/install -r requirements.lock
# 2) Hash-locked build backend, then our own package without resolving anything new.
COPY requirements-build.lock ./
RUN pip install --require-hashes --only-binary=:all: -r requirements-build.lock
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-deps --no-build-isolation --prefix=/install .

FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 DATA_DIR=/data PORT=8000
COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown app:app /data && chmod 700 /data \
 && pip uninstall -y pip setuptools wheel 2>/dev/null || true
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,os;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8000\")}/healthz',timeout=4)"
CMD ["garmin-mcp"]
