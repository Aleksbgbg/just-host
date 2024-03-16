# backend
FROM rust:alpine AS backend

WORKDIR /backend

RUN apk add --update --no-cache musl-dev libpq-dev

COPY backend /backend
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release --package just-host

# frontend
FROM node:alpine AS frontend

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json /frontend/
RUN npm install

COPY frontend /frontend
RUN npm run build

# prod
FROM alpine:latest

WORKDIR /app

RUN apk add --update --no-cache libc++ libpq

COPY --from=backend /backend/target/release/just-host /app/backend
COPY --from=frontend /frontend/dist /app/frontend
COPY backend/.env.toml /app

EXPOSE 8601

ENTRYPOINT ["/app/backend"]
