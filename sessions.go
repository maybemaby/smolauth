package smolauth

import (
	"errors"
	"net/http"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated")
)

func (am *AuthManager) Login(r *http.Request, data SessionData) error {
	err := am.SessionManager.RenewToken(r.Context())

	if err != nil {
		return err
	}

	am.SessionManager.Put(r.Context(), SessionUserIdKey, data.UserId)

	return nil
}

func (am *AuthManager) Logout(r *http.Request) error {

	err := am.SessionManager.RenewToken(r.Context())

	if err != nil {
		return err
	}

	return am.SessionManager.Destroy(r.Context())
}

func (am *AuthManager) GetUser(r *http.Request) (ReadUser, error) {
	userId := am.SessionManager.GetInt(r.Context(), SessionUserIdKey)

	if userId == 0 {
		return ReadUser{}, ErrUnauthenticated
	}

	return am.getUserById(userId)
}
