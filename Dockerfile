FROM python:3.13-slim AS build
WORKDIR /app
RUN pip install --no-cache-dir --upgrade pip
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    PORT=8000
COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 --home /nonexistent app \
 && mkdir -p /data && chown app /data
USER app
EXPOSE 8000
CMD ["garmin-mcp"]
