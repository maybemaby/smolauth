package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"github.com/maybemaby/smolauth"
	samples "github.com/maybemaby/smolauth/samples/common"
)

func main() {

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
	password_hash TEXT NOT NULL,
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
	access_token_expires_at INTEGER NOT NULL
);

CREATE TABLE sessions (
	token TEXT PRIMARY KEY,
	data BLOB NOT NULL,
	expiry REAL NOT NULL
);
	`)

	if err != nil {
		log.Fatal(err)
		return
	}

	am := smolauth.NewAuthManager(smolauth.AuthOpts{})

	am.WithSqlite(db)

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

		err = am.CheckPassword(data.Email, data.Password)

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

	err = http.ListenAndServe(":8000", mux)

	if err != nil {
		log.Fatal(err)
		return
	}
}
