package smolauth

import (
	"database/sql"
	"testing"

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

type ProviderSqliteSuite struct {
	suite.Suite
	db      *sql.DB
	manager *AuthManager
}

func (s *ProviderSqliteSuite) SetupSuite() {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		s.T().Fatal(err)
	}

	s.db = db

	_, err = db.Exec(SetupSqlite)

	if err != nil {
		s.T().Fatal(err)
	}

	manager := NewAuthManager(AuthOpts{})
	manager.WithSqlite(db)

	s.manager = manager
}

func (s *ProviderSqliteSuite) TearDownSuite() {
	s.db.Close()
}

// Verify with this query that if a user without a provider is found, it returns a partial user account
func (s *ProviderSqliteSuite) TestGetUserAccountIncomplete() {
	id, err := s.manager.PasswordSignup("emptyacc", "password")

	if err != nil {
		s.T().Fatal(err)
	}

	user, err := s.manager.getUserAccount("emptyacc", "google")

	if err != nil {
		s.T().Fatal(err)
	}

	assert.NotNil(s.T(), user.Email)
	assert.Equal(s.T(), id, user.Id)
	assert.Nil(s.T(), user.Provider)
	assert.Nil(s.T(), user.ProviderId)
}

func (s *ProviderSqliteSuite) TestGetUserAccountComplete() {
	id, err := s.manager.PasswordSignup("completeacc", "password")

	if err != nil {
		s.T().Fatal(err)
	}

	_, err = s.manager.db.Exec("INSERT INTO accounts (user_id, provider, provider_id, access_token, access_token_expires_at) VALUES (?, 'google', '12345', 'token', 0)", id)

	if err != nil {
		s.T().Fatal(err)
	}

	user, err := s.manager.getUserAccount("completeacc", "google")

	if err != nil {
		s.T().Fatal(err)
	}

	assert.NotNil(s.T(), user.Email)
	assert.Equal(s.T(), id, user.Id)
	assert.Equal(s.T(), "google", *user.Provider)
	assert.Equal(s.T(), "12345", *user.ProviderId)
}

func TestProviderSqliteSuite(t *testing.T) {
	suite.Run(t, new(ProviderSqliteSuite))
}
