package smolauth_test

import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	"github.com/alexedwards/scs/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/maybemaby/smolauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const SetupSqlite = `
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
`

const SetupPostgres = `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
		email TEXT UNIQUE,
		password_hash TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS accounts (
		id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		provider TEXT NOT NULL,
		provider_id TEXT NOT NULL,
		access_token TEXT NOT NULL,
		refresh_token TEXT,
		access_token_expires_at TIMESTAMPTZ NOT NULL
	);

	CREATE UNIQUE INDEX IF NOT EXISTS accounts_provider_provider_id_idx ON accounts (provider, provider_id);

	CREATE TABLE IF NOT EXISTS sessions (
		token TEXT PRIMARY KEY,
		data BYTEA NOT NULL,
		expiry TIMESTAMPTZ NOT NULL
	);

	CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expiry);
	`

type AuthManagerSqliteSuite struct {
	suite.Suite
	db      *sql.DB
	manager *smolauth.AuthManager
}

func (suite *AuthManagerSqliteSuite) SetupTest() {
	db, err := sql.Open("sqlite3", ":memory:")

	if err != nil {
		suite.T().Fatal(err)
	}

	suite.db = db

	_, err = db.Exec(SetupSqlite)

	if err != nil {
		suite.T().Fatal(err)
	}

	manager := smolauth.NewAuthManager(smolauth.AuthOpts{})
	manager.WithSqlite(db)

	suite.manager = manager
}

func (suite *AuthManagerSqliteSuite) TestSessionManagerCookieDefaults() {
	manager := smolauth.NewAuthManager(smolauth.AuthOpts{
		Cookie: scs.SessionCookie{
			HttpOnly: true,
			Persist:  true,
		},
	})

	assert.Equal(suite.T(), "/", manager.SessionManager.Cookie.Path)
	assert.Equal(suite.T(), "session", manager.SessionManager.Cookie.Name)
	assert.Equal(suite.T(), http.SameSiteLaxMode, manager.SessionManager.Cookie.SameSite)
	assert.False(suite.T(), manager.SessionManager.Cookie.Secure)
}

func (suite *AuthManagerSqliteSuite) TestPasswordSignup() {
	id, err := suite.manager.PasswordSignup("email", "password")
	assert.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), 0, id)
}

func (suite *AuthManagerSqliteSuite) TestPasswordSignupDupeReturnsError() {
	id, err := suite.manager.PasswordSignup("emaildupe", "password")
	assert.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), 0, id)

	id, err = suite.manager.PasswordSignup("emaildupe", "password")
	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrUserExists)
	assert.Equal(suite.T(), 0, id)
}

func (suite *AuthManagerSqliteSuite) TestCheckPassword() {
	suite.manager.PasswordSignup("emailpass", "password")

	id, err := suite.manager.CheckPassword("emailpass", "password")

	assert.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), 0, id)
}

func (suite *AuthManagerSqliteSuite) TestCheckPasswordInvalidEmail() {
	id, err := suite.manager.CheckPassword("none", "password")

	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrInvalidEmail)
	assert.Equal(suite.T(), 0, id)
}

func (suite *AuthManagerSqliteSuite) TestCheckPasswordInvalidPassword() {
	suite.manager.PasswordSignup("emailpassinvalid", "password")

	id, err := suite.manager.CheckPassword("emailpassinvalid", "wrongpassword")

	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrInvalidPassword)
	assert.Equal(suite.T(), 0, id)
}

func (suite *AuthManagerSqliteSuite) TearDownTest() {
	suite.db.Close()
}

func TestAuthManagerSqliteSuite(t *testing.T) {
	suite.Run(t, new(AuthManagerSqliteSuite))
}

type AuthManagerPostgresSuite struct {
	suite.Suite
	db      *sql.DB
	manager *smolauth.AuthManager
}

func (suite *AuthManagerPostgresSuite) SetupTest() {
	pool, err := pgxpool.New(context.Background(), "postgres://postgres:postgres@localhost:5432/smolauth")

	db := stdlib.OpenDBFromPool(pool)

	if err != nil {
		suite.T().Fatal(err)
	}

	suite.db = db

	_, err = db.Exec(SetupPostgres)

	if err != nil {
		suite.T().Fatal(err)
	}

	manager := smolauth.NewAuthManager(smolauth.AuthOpts{})
	manager.WithPostgres(pool)

	suite.manager = manager
}

func (suite *AuthManagerPostgresSuite) TestPasswordSignup() {
	id, err := suite.manager.PasswordSignup("email", "password")
	assert.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), 0, id)
}

func (suite *AuthManagerPostgresSuite) TestPasswordSignupDupeReturnsError() {
	id, err := suite.manager.PasswordSignup("emaildupe", "password")
	assert.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), 0, id)

	id, err = suite.manager.PasswordSignup("emaildupe", "password")
	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrUserExists)
	assert.Equal(suite.T(), 0, id)
}

func (suite *AuthManagerPostgresSuite) TestCheckPassword() {
	suite.manager.PasswordSignup("emailpass", "password")

	id, err := suite.manager.CheckPassword("emailpass", "password")

	assert.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), 0, id)
}

func (suite *AuthManagerPostgresSuite) TestCheckPasswordInvalidEmail() {
	id, err := suite.manager.CheckPassword("none", "password")

	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrInvalidEmail)
	assert.Equal(suite.T(), 0, id)
}

func (suite *AuthManagerPostgresSuite) TestCheckPasswordInvalidPassword() {
	suite.manager.PasswordSignup("emailpassinvalid", "password")

	id, err := suite.manager.CheckPassword("emailpassinvalid", "wrongpassword")

	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrInvalidPassword)
	assert.Equal(suite.T(), 0, id)
}

func (suite *AuthManagerPostgresSuite) TearDownTest() {
	suite.db.Close()
}

func TestAuthManagerPostgresSuite(t *testing.T) {
	suite.Run(t, new(AuthManagerPostgresSuite))
}
