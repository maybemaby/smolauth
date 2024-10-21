# smolauth

A small and opinionated auth package for go. Designed to suit just my needs.

May suit your needs if you:
- Use session-based authentication
- Use net/http
- Use sqlite or postgres for storing user and session data

## Features
- Login/Logout sessions
- Password hashing
- Auth middleware
- OAuth providers
  - Google
  - Github
  - Facebook

### Not-Features
- Validation (password strength, password confirmation, email format, etc)
- Email verification
- Forgot password
- 

## SQL Schemas

If you need extended user or account schemas, I suggest using a one-to-one table relationship or optional columns should be fine.

### Sqlite

```sql
CREATE TABLE users (
	id INTEGER PRIMARY KEY NOT NULL,
	email TEXT UNIQUE,
	password_hash TEXT,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
	id INTEGER PRIMARY KEY NOT NULL,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	provider TEXT NOT NULL,
	provider_id TEXT NOT NULL,
	access_token TEXT NOT NULL,
	refresh_token TEXT,
	access_token_expires_at DATETIME NOT NULL
);

CREATE UNIQUE INDEX accounts_provider_provider_id_idx ON accounts (provider, provider_id);

CREATE TABLE sessions (
	token TEXT PRIMARY KEY,
	data BLOB NOT NULL,
	expiry REAL NOT NULL
);

CREATE INDEX sessions_expiry_idx ON sessions(expiry);
```

### Postgresql

```sql
CREATE TABLE users (
	id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	email TEXT UNIQUE,
	password_hash TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
	id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
	provider TEXT NOT NULL,
	provider_id TEXT NOT NULL,
	access_token TEXT NOT NULL,
	refresh_token TEXT,
	access_token_expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX accounts_provider_provider_id_idx ON accounts (provider, provider_id);

CREATE TABLE sessions (
	token TEXT PRIMARY KEY,
	data BYTEA NOT NULL,
	expiry TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_expiry_idx ON sessions (expiry);
```

## TODO
- [ ] Handle existing user when linking account