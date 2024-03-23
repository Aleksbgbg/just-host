CREATE TYPE authority AS ENUM ('owner', 'admin', 'none');

CREATE TABLE IF NOT EXISTS users (
    id INT8 PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    auth_secret BYTEA NOT NULL,
    authority authority NOT NULL
);

SELECT diesel_manage_updated_at('users');
