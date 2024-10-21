package smolauth_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/maybemaby/smolauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func OkHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type MiddlewareSuite struct {
	suite.Suite
	manager *smolauth.AuthManager
	db      *sql.DB
}

func (suite *MiddlewareSuite) SetupTest() {
	db, err := sql.Open("sqlite3", ":memory:")

	if err != nil {
		suite.T().Fatal(err)
	}

	_, err = db.Exec(SetupSqlite)

	if err != nil {
		suite.T().Fatal(err)
	}

	suite.db = db

	manager := smolauth.NewAuthManager(smolauth.AuthOpts{})

	manager.WithSqlite(db)

	suite.manager = manager
}

func (suite *MiddlewareSuite) TestAuthLoadMiddleware() {
	middleware := smolauth.AuthLoadMiddleware(suite.manager)
	handler := middleware.ThenFunc(func(w http.ResponseWriter, r *http.Request) {
		status := suite.manager.SessionManager.Status(r.Context())

		assert.NotEqual(suite.T(), 0, status, "Just checking the session manager is loaded properly and accessible from the context")
	})

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8000/", nil)

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(suite.T(), http.StatusOK, resp.StatusCode)
}

func (suite *MiddlewareSuite) TestRequireAuthMiddleware() {
	middleware := smolauth.AuthLoadMiddleware(suite.manager).Append(smolauth.RequireAuthMiddleware(suite.manager))
	handler := middleware.Then(http.HandlerFunc(OkHandler))

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8000/", nil)

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()

	assert.Equal(suite.T(), http.StatusUnauthorized, resp.StatusCode)
}

func (suite *MiddlewareSuite) TearDownTest() {
	suite.db.Close()
}

func TestMiddlewareSuite(t *testing.T) {
	suite.Run(t, new(MiddlewareSuite))
}
