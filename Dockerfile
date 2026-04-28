# --- build image

FROM docker.io/rust:alpine AS builder

RUN apk add \
    musl-dev \
    build-base \
    cmake \
    pkgconf \
    sqlite-dev \
    xz-dev

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "10001" \
    "app"

WORKDIR /app
COPY . .

RUN cargo install --locked --root /out --path . --features container

# --- final image

FROM scratch

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

WORKDIR /app
COPY --from=builder /out/bin/apt-cacher-rs /app/apt-cacher-rs
USER app:app
VOLUME ["/data"]
EXPOSE 3142/tcp
CMD ["/app/apt-cacher-rs"]
