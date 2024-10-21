package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/maybemaby/smolauth"
	samples "github.com/maybemaby/smolauth/samples/common"
)

var GOOGLE_CLIENT_ID string
var GOOGLE_CLIENT_SECRET string
var GOOGLE_REDIRECT_URL string

var GITHUB_CLIENT_ID string
var GITHUB_CLIENT_SECRET string
var GITHUB_REDIRECT_URL string

func loadEnv() {
	GOOGLE_CLIENT_ID = os.Getenv("GOOGLE_CLIENT_ID")
	GOOGLE_CLIENT_SECRET = os.Getenv("GOOGLE_CLIENT_SECRET")
	GOOGLE_REDIRECT_URL = os.Getenv("GOOGLE_REDIRECT_URI")

	GITHUB_CLIENT_ID = os.Getenv("GITHUB_CLIENT_ID")
	GITHUB_CLIENT_SECRET = os.Getenv("GITHUB_CLIENT_SECRET")
	GITHUB_REDIRECT_URL = os.Getenv("GITHUB_REDIRECT_URI")
}

func sqliteMain() {
	db, err := sql.Open("sqlite3", ":memory:")

	if err != nil {
		log.Fatal(err)
		return
	}

	defer db.Close()

	_, err = db.Exec(`
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

CREATE INDEX sessions_expiry_idx ON sessions(expiry);`)

	if err != nil {
		log.Fatal(err)
		return
	}

	googleProvider := smolauth.NewGoogleProvider(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URL, "http://localhost:8000/me", []string{})
	githubProvider := smolauth.NewGithubProvider(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URL, "http://localhost:8000/me", []string{})

	am := smolauth.NewAuthManager(smolauth.AuthOpts{})

	am.WithSqlite(db)
	am.WithGoogle(googleProvider)
	am.WithGithub(githubProvider)
	am.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	id, err := am.PasswordSignup("username@email.com", "password123")

	if err != nil {
		log.Fatal(err)
		return
	}

	log.Println("User ID:", id)

	mux := http.NewServeMux()

	mw := smolauth.AuthLoadMiddleware(am)
	authMw := mw.Append(smolauth.RequireAuthMiddleware(am))

	mux.Handle("POST /signup/{$}", mw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// For a real situation should do other checks here, like password strength, password match, etc.
		var data samples.LoginData

		err := json.NewDecoder(r.Body).Decode(&data)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		id, err := am.PasswordSignup(data.Email, data.Password)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = am.Login(r, smolauth.SessionData{UserId: id})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Signed up"))
	}))

	mux.Handle("POST /login/{$}", mw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		var data samples.LoginData

		err := json.NewDecoder(r.Body).Decode(&data)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		id, err = am.CheckPassword(data.Email, data.Password)

		if err != nil {
			log.Printf("Error checking password: %v\n", err)
			http.Error(w, "Invalid login", http.StatusUnauthorized)
			return
		}

		err = am.Login(r, smolauth.SessionData{UserId: id})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	mux.Handle("POST /logout/{$}", mw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		err := am.Logout(r)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Logged out"))
	}))

	mux.Handle("GET /me/{$}", authMw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := am.GetUser(r)

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		json.NewEncoder(w).Encode(user)
	}))

	mux.Handle("GET /auth/google/{$}", mw.ThenFunc(am.HandleOAuth("google")))
	mux.Handle("GET /auth/google/callback/{$}", mw.ThenFunc(am.HandleOAuthCallback("google")))
	mux.Handle("GET /auth/github/{$}", mw.ThenFunc(am.HandleOAuth("github")))
	mux.Handle("GET /auth/github/callback/{$}", mw.ThenFunc(am.HandleOAuthCallback("github")))

	err = http.ListenAndServe(":8000", mux)

	if err != nil {
		log.Fatal(err)
		return
	}
}

func postgresMain() {
	pool, err := pgxpool.New(context.Background(), "postgres://postgres:postgres@localhost:5432/smolauth")

	if err != nil {
		log.Fatal(err)
		return
	}

	db := stdlib.OpenDBFromPool(pool)

	defer db.Close()
	defer pool.Close()

	_, err = db.Exec(`
CREATE TABLE users (
	id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	email TEXT UNIQUE,
	password_hash TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
	expiry TIMESTAMPTZ NOT NULL,
);

CREATE INDEX sessions_expiry_idx ON sessions (expiry);
`)

	if err != nil {
		log.Fatal(err)
		return
	}

	googleProvider := smolauth.NewGoogleProvider(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URL, "http://localhost:8000/me", []string{})

	am := smolauth.NewAuthManager(smolauth.AuthOpts{})

	am.WithSqlite(db)
	am.WithGoogle(googleProvider)

	id, err := am.PasswordSignup("username@email.com", "password123")

	if err != nil {
		log.Fatal(err)
		return
	}

	log.Println("User ID:", id)

	mux := http.NewServeMux()

	mw := smolauth.AuthLoadMiddleware(am)
	authMw := mw.Append(smolauth.RequireAuthMiddleware(am))

	mux.Handle("POST /signup/{$}", mw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		// For a real situation should do other checks here, like password strength, password match, etc.
		var data samples.LoginData

		err := json.NewDecoder(r.Body).Decode(&data)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		id, err := am.PasswordSignup(data.Email, data.Password)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = am.Login(r, smolauth.SessionData{UserId: id})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Signed up"))
	}))

	mux.Handle("POST /login/{$}", mw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		var data samples.LoginData

		err := json.NewDecoder(r.Body).Decode(&data)

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		id, err = am.CheckPassword(data.Email, data.Password)

		if err != nil {
			log.Printf("Error checking password: %v\n", err)
			http.Error(w, "Invalid login", http.StatusUnauthorized)
			return
		}

		err = am.Login(r, smolauth.SessionData{UserId: id})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	mux.Handle("POST /logout/{$}", mw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		err := am.Logout(r)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("Logged out"))
	}))

	mux.Handle("GET /me/{$}", authMw.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := am.GetUser(r)

		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		json.NewEncoder(w).Encode(user)
	}))

	mux.Handle("GET /google/{$}", am.HandleOAuth("google"))
	mux.Handle("GET /google/callback/{$}", am.HandleOAuthCallback("google"))

	err = http.ListenAndServe(":8000", mux)

	if err != nil {
		log.Fatal(err)
		return
	}
}

func main() {

	loadEnv()

	args := os.Args[1:]

	if args[0] == "sqlite" {
		sqliteMain()
	} else {
		postgresMain()
	}
}
