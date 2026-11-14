FROM python:3.12-slim-bookworm AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --only-binary=cryptography,cffi .


FROM python:3.12-slim-bookworm AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

COPY --from=builder /opt/venv /opt/venv

WORKDIR /work
RUN chown 65532:65532 /work
USER 65532:65532

ENTRYPOINT ["tacstmu"]
CMD ["--help"]
