# --- build image

FROM docker.io/rust:alpine AS builder

RUN apk add --no-cache \
    musl-dev \
    build-base \
    cmake \
    pkgconf

# Both are seeded into the scratch image below; /data must exist there owned by
# the daemon, or a fresh named volume is created root-owned and unwritable.
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "10001" \
    "app" \
 && mkdir -p /data/cache

WORKDIR /app
COPY . .

ENV SQLX_OFFLINE=true
RUN cargo install --locked --root /out --path . --features webpki-roots

# --- final image

FROM scratch

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder --chown=10001:10001 /data /data

WORKDIR /app
COPY --from=builder /out/bin/apt-cacher-rs /app/apt-cacher-rs
USER app:app
VOLUME ["/data"]
EXPOSE 3142/tcp
ENTRYPOINT ["/app/apt-cacher-rs", \
            "--config-file=/app/apt-cacher-rs.conf", \
            "--cache-path=/data/cache", \
            "--database-path=/data/apt-cacher-rs.db"]
CMD []
