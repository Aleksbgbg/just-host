# backend
FROM rust:alpine AS backend

WORKDIR /backend

COPY backend /backend

RUN cargo build --release

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

COPY --from=backend /backend/target/release/just-host /app/backend
COPY --from=frontend /frontend/dist /app/frontend

ENTRYPOINT ["/app/backend"]
