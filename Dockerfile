FROM rust:1-bookworm AS native
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY rules ./rules
RUN cargo build --locked --release --bin jocky

FROM node:22-bookworm-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM python:3.12-slim-bookworm
WORKDIR /app
COPY backend/requirements.lock backend/requirements.lock
RUN pip install --no-cache-dir -r backend/requirements.lock
COPY backend ./backend
COPY examples ./examples
COPY fixtures ./fixtures
COPY rules ./rules
COPY --from=native /build/target/release/jocky /usr/local/bin/jocky
COPY --from=frontend /build/dist ./frontend/dist
RUN useradd --uid 10001 --create-home jocky && mkdir -p /var/lib/jocky/data /var/lib/jocky/keys && chown -R jocky:jocky /var/lib/jocky
ENV JOCKY_DATA=/var/lib/jocky/data JOCKY_KEY_PATH=/var/lib/jocky/keys/checkpoint.key JOCKY_WORKER=/usr/local/bin/jocky
USER jocky
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3)"
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "*"]
