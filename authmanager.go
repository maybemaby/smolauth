package smolauth

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/pgxstore"
	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

const SessionUserIdKey = "user_id"

var (
	ErrUserExists      = errors.New("user already exists with that email")
	ErrInvalidEmail    = errors.New("invalid email")
	ErrInvalidPassword = errors.New("invalid password")
)

type AuthManager struct {
	// SessionManager from https://github.com/alexedwards/scs, can be assigned to a custom session manager,
	// only guaranteed to work with pgxstore and sqlite3store
	SessionManager *scs.SessionManager
	db             *sql.DB
	databaseType   string
	providers      map[string]OAuthProvider
}

type AuthOpts struct {
	Cookie          scs.SessionCookie
	SessionDuration time.Duration
}

type SessionData struct {
	// UserId is the primary key of the user in the database
	UserId int
}

func NewAuthManager(opts AuthOpts) *AuthManager {

	sessionManager := scs.New()

	if (opts.Cookie != scs.SessionCookie{}) {
		sessionManager.Cookie = opts.Cookie
	} else {
		sessionManager.Cookie.Name = "smolauth_sess"
		sessionManager.Cookie.HttpOnly = true
		sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	}

	if opts.SessionDuration != 0 {
		sessionManager.Lifetime = opts.SessionDuration
	} else {
		sessionManager.Lifetime = time.Hour * 24 * 7
	}

	return &AuthManager{SessionManager: sessionManager, providers: make(map[string]OAuthProvider)}
}

func (am *AuthManager) WithSqlite(db *sql.DB) {
	store := sqlite3store.New(db)

	am.SessionManager.Store = store
	am.db = db
	am.databaseType = "sqlite"
}

func (am *AuthManager) WithPostgres(pool *pgxpool.Pool) {
	store := pgxstore.New(pool)

	am.SessionManager.Store = store

	db := stdlib.OpenDBFromPool(pool)

	am.db = db
	am.databaseType = "postgres"
}

const insertUserQuerySqlite = `INSERT into USERS (email, password_hash) VALUES (? ,?) RETURNING id`

const insertUserQueryPostgres = `INSERT into USERS (email, password_hash) VALUES ($1 , $2) RETURNING id`

func (am *AuthManager) insertUser(email sql.NullString, passwordHash sql.NullString) (int, error) {
	var err error
	var id int
	var stmt *sql.Stmt

	if am.databaseType == "sqlite" {
		stmt, err = am.db.Prepare(insertUserQuerySqlite)
	} else if am.databaseType == "postgres" {
		stmt, err = am.db.Prepare(insertUserQueryPostgres)
	}

	if err != nil {
		return 0, err
	}

	err = stmt.QueryRow(email, passwordHash).Scan(&id)

	return id, err
}

type UserAccount struct {
	Provider             string
	ProviderId           string
	AccessToken          string
	RefreshToken         string
	Email                string
	AccessTokenExpiresAt time.Time
}

const insertUserNoPassSqlite = `INSERT into USERS (email) VALUES (?) RETURNING id`
const insertUserNoPassPostgres = `INSERT into USERS (email) VALUES ($1) RETURNING id`

const insertAccountSqlite = `
INSERT into accounts (user_id, provider, provider_id, access_token, refresh_token, access_token_expires_at)
VALUES (?, ?, ?, ?, ?, ?)
`

const insertAccountPostgres = `
INSERT into accounts (user_id, provider, provider_id, access_token, refresh_token, access_token_expires_at)
VALUES ($1, $2, $3, $4, $5, $6)`

func (am *AuthManager) insertUserAccount(user UserAccount) (int, error) {
	var userId int
	tx, err := am.db.Begin()

	if err != nil {
		return 0, err
	}

	defer tx.Rollback()

	var userStmt *sql.Stmt

	if am.databaseType == "sqlite" {
		userStmt, err = tx.Prepare(insertUserNoPassSqlite)
	} else {
		userStmt, err = tx.Prepare(insertUserNoPassPostgres)
	}

	if err != nil {
		return 0, err
	}

	defer userStmt.Close()

	err = userStmt.QueryRow(user.Email).Scan(&userId)

	if err != nil {
		return 0, err
	}

	var accountStmt *sql.Stmt

	if am.databaseType == "sqlite" {
		accountStmt, err = tx.Prepare(insertAccountSqlite)
	} else {
		accountStmt, err = tx.Prepare(insertAccountPostgres)
	}

	if err != nil {
		return 0, err
	}

	defer accountStmt.Close()

	_, err = accountStmt.Exec(userId, user.Provider, user.ProviderId, user.AccessToken, user.RefreshToken, user.AccessTokenExpiresAt)

	if err != nil {
		return 0, err
	}

	err = tx.Commit()

	if err != nil {
		return 0, err
	}

	return userId, nil
}

func (am *AuthManager) PasswordSignup(email string, password string) (int, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return 0, err
	}

	id, err := am.insertUser(sql.NullString{
		String: email,
		Valid:  true,
	}, sql.NullString{
		String: string(hash),
		Valid:  true,
	})

	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrUserExists
		}

		return 0, err
	}

	return id, nil
}

const checkPasswordQuerySqlite = `SELECT id, password_hash FROM users WHERE email = ? LIMIT 1`
const checkPasswordQueryPostgres = `SELECT id, password_hash FROM users WHERE email = $1 LIMIT 1`

// CheckPassword checks if the password is correct for the given email
// Returns user id if the password is correct to be used in the session
// Returns ErrInvalidEmail if the user with email is not found
// Returns ErrInvalidPassword if the password doesn't match the hash
func (am *AuthManager) CheckPassword(email string, password string) (int, error) {
	var id int
	var hash string
	var err error
	var stmt *sql.Stmt

	if am.databaseType == "sqlite" {
		stmt, err = am.db.Prepare(checkPasswordQuerySqlite)
	} else if am.databaseType == "postgres" {
		stmt, err = am.db.Prepare(checkPasswordQueryPostgres)
	}

	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	err = stmt.QueryRow(email).Scan(&id, &hash)

	if err != nil {
		return 0, ErrInvalidEmail
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))

	if err != nil {
		return 0, ErrInvalidPassword
	}

	return id, nil
}

type ReadUser struct {
	Id        int       `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

const getUserByIdSqlite = `SELECT id, email, created_at FROM users WHERE id = ? LIMIT 1`
const getUserByIdPostgres = `SELECT id, email, created_at FROM users WHERE id = $1 LIMIT 1`

func (am *AuthManager) getUserById(id int) (ReadUser, error) {
	var user ReadUser
	var err error
	var stmt *sql.Stmt

	if am.databaseType == "sqlite" {
		stmt, err = am.db.Prepare(getUserByIdSqlite)
	} else if am.databaseType == "postgres" {
		stmt, err = am.db.Prepare(getUserByIdPostgres)
	}

	if err != nil {
		return user, err
	}

	defer stmt.Close()

	err = stmt.QueryRow(id).Scan(&user.Id, &user.Email, &user.CreatedAt)

	return user, err
}

func (am *AuthManager) ThirdPartySignup(user UserAccount) (int, error) {
	return am.insertUserAccount(user)
}
