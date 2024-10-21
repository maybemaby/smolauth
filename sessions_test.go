package smolauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alexedwards/scs/v2/memstore"
	"github.com/maybemaby/smolauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SessionsTestSuite struct {
	suite.Suite
	manager *smolauth.AuthManager
}

func (suite *SessionsTestSuite) SetupTest() {
	manager := smolauth.NewAuthManager(smolauth.AuthOpts{})

	// returnFind := make(map[string][]byte)

	// returnFind["ok"] = []byte(`{"UserId":1}`)

	// returnDelete := make(map[string]error)

	// returnDelete["ok"] = nil
	// returnDelete["error"] = errors.New("mock error")

	manager.SessionManager.Store = memstore.New()
	suite.manager = manager
}

func (suite *SessionsTestSuite) TestLoginOk() {
	req := httptest.NewRequest("POST", "http://localhost:8000/login", nil)
	rec := httptest.NewRecorder()

	mw := smolauth.AuthLoadMiddleware(suite.manager)

	loginHandler := func(w http.ResponseWriter, r *http.Request) {

		suite.manager.Login(r, smolauth.SessionData{UserId: 1})

		w.WriteHeader(http.StatusOK)
	}

	handler := mw.ThenFunc(loginHandler)

	handler.ServeHTTP(rec, req)

	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	cookies := rec.Result().Cookies()

	authReq := httptest.NewRequest("GET", "http://localhost:8000/auth", nil)
	authReq.AddCookie(cookies[0])
	authRec := httptest.NewRecorder()

	authHandler := func(w http.ResponseWriter, r *http.Request) {

		userId := suite.manager.SessionManager.GetInt(r.Context(), smolauth.SessionUserIdKey)

		assert.Equal(suite.T(), 1, userId)

		w.WriteHeader(http.StatusOK)
	}

	authHandlerFunc := mw.ThenFunc(authHandler)

	authHandlerFunc.ServeHTTP(rec, authReq)

	assert.Equal(suite.T(), http.StatusOK, authRec.Code)
}

func (suite *SessionsTestSuite) TestLogout() {
	req := httptest.NewRequest("POST", "http://localhost:8000/login", nil)
	rec := httptest.NewRecorder()

	mw := smolauth.AuthLoadMiddleware(suite.manager)

	loginHandler := func(w http.ResponseWriter, r *http.Request) {

		suite.manager.Login(r, smolauth.SessionData{UserId: 1})

		w.WriteHeader(http.StatusOK)
	}

	handler := mw.ThenFunc(loginHandler)

	handler.ServeHTTP(rec, req)

	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	cookies := rec.Result().Cookies()

	logoutReq := httptest.NewRequest("POST", "http://localhost:8000/logout", nil)
	logoutReq.AddCookie(cookies[0])

	logoutRec := httptest.NewRecorder()

	logoutHandler := func(w http.ResponseWriter, r *http.Request) {

		err := suite.manager.Logout(r)

		assert.Nil(suite.T(), err)

		w.WriteHeader(http.StatusOK)
	}

	logoutHandlerFunc := mw.ThenFunc(logoutHandler)

	logoutHandlerFunc.ServeHTTP(logoutRec, logoutReq)

	assert.Equal(suite.T(), http.StatusOK, logoutRec.Code)

	authReq := httptest.NewRequest("GET", "http://localhost:8000/auth", nil)
	authReq.AddCookie(logoutReq.Cookies()[0])
	authRec := httptest.NewRecorder()

	authHandler := func(w http.ResponseWriter, r *http.Request) {

		userId := suite.manager.SessionManager.GetInt(r.Context(), smolauth.SessionUserIdKey)

		assert.Equal(suite.T(), 0, userId)

		if userId == 0 {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}

	authHandlerFunc := mw.ThenFunc(authHandler)

	authHandlerFunc.ServeHTTP(authRec, authReq)

	assert.Equal(suite.T(), http.StatusUnauthorized, authRec.Code)

}

func TestSessionTestSuite(t *testing.T) {
	suite.Run(t, new(SessionsTestSuite))
}
