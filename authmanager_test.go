package smolauth_test

import (
	"database/sql"
	"testing"

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

	err := suite.manager.CheckPassword("emailpass", "password")

	assert.NoError(suite.T(), err)
}

func (suite *AuthManagerSqliteSuite) TestCheckPasswordInvalidEmail() {
	err := suite.manager.CheckPassword("none", "password")

	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrInvalidEmail)
}

func (suite *AuthManagerSqliteSuite) TestCheckPasswordInvalidPassword() {
	suite.manager.PasswordSignup("emailpassinvalid", "password")

	err := suite.manager.CheckPassword("emailpassinvalid", "wrongpassword")

	assert.Error(suite.T(), err)
	assert.ErrorIs(suite.T(), err, smolauth.ErrInvalidPassword)
}

func (suite *AuthManagerSqliteSuite) TearDownTest() {
	suite.db.Close()
}

func TestAuthManagerSqliteSuite(t *testing.T) {
	suite.Run(t, new(AuthManagerSqliteSuite))
}
