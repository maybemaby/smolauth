package smolauth_test

import (
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2/memstore"
	"github.com/maybemaby/smolauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SessionsTestSuite struct {
	suite.Suite
	manager *smolauth.AuthManager
}

type extraData struct {
	Name     string
	IsAdmin  bool
	ExpireAt time.Time
}

var extra = extraData{
	Name:     "John Doe",
	IsAdmin:  true,
	ExpireAt: time.Now().Add(time.Hour * 24),
}

func (suite *SessionsTestSuite) SetupTest() {
	manager := smolauth.NewAuthManager(smolauth.AuthOpts{})

	manager.SessionManager.Store = memstore.New()
	suite.manager = manager

	gob.Register(extraData{})
}

func (suite *SessionsTestSuite) TestLoginOk() {
	req := httptest.NewRequest("POST", "http://localhost:8000/login", nil)
	rec := httptest.NewRecorder()

	mw := smolauth.AuthLoadMiddleware(suite.manager)

	loginHandler := func(w http.ResponseWriter, r *http.Request) {

		suite.manager.Login(r, smolauth.SessionData{UserId: 1, Extra: extra})

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
		extra := suite.manager.SessionManager.Get(r.Context(), smolauth.SessionExtraKey)

		assert.Equal(suite.T(), 1, userId)
		assert.IsType(suite.T(), extraData{}, extra)

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

		suite.manager.Login(r, smolauth.SessionData{UserId: 1, Extra: extra})

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
		extraStuff := suite.manager.SessionManager.Get(r.Context(), smolauth.SessionExtraKey)

		assert.Equal(suite.T(), 0, userId)
		assert.Nil(suite.T(), extraStuff)

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
