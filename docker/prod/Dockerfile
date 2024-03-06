# backend
FROM rust:alpine AS backend

WORKDIR /backend

COPY backend /backend

RUN cargo build --release

# prod
FROM alpine:latest

WORKDIR /app

COPY --from=backend /backend/target/release/just-host /app/backend

ENTRYPOINT ["/app/backend"]
