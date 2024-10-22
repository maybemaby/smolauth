package smolauth

import (
	"context"
	"errors"
	"net/http"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated")
)

const SessionExtraKey = "extra"

func (am *AuthManager) Login(r *http.Request, data SessionData) error {
	return am.LoginCtx(r.Context(), data)
}

func (am *AuthManager) LoginCtx(ctx context.Context, data SessionData) error {
	err := am.SessionManager.RenewToken(ctx)

	if err != nil {
		return err
	}

	am.SessionManager.Put(ctx, SessionUserIdKey, data.UserId)
	am.SessionManager.Put(ctx, SessionExtraKey, data.Extra)

	return nil
}

func (am *AuthManager) LogoutCtx(ctx context.Context) error {

	err := am.SessionManager.RenewToken(ctx)

	if err != nil {
		return err
	}

	return am.SessionManager.Destroy(ctx)
}

func (am *AuthManager) Logout(r *http.Request) error {
	return am.LogoutCtx(r.Context())
}

func (am *AuthManager) GetUserCtx(ctx context.Context) (ReadUser, error) {
	userId := am.SessionManager.GetInt(ctx, SessionUserIdKey)

	if userId == 0 {
		return ReadUser{}, ErrUnauthenticated
	}

	return am.getUserById(userId)
}

func (am *AuthManager) GetUser(r *http.Request) (ReadUser, error) {
	return am.GetUserCtx(r.Context())
}

func (am *AuthManager) GetSessionCtx(ctx context.Context) (SessionData, error) {
	userId := am.SessionManager.GetInt(ctx, SessionUserIdKey)

	return SessionData{
		UserId: userId,
		Extra:  am.SessionManager.Get(ctx, SessionExtraKey),
	}, nil
}

func (am *AuthManager) GetSession(r *http.Request) (SessionData, error) {
	return am.GetSessionCtx(r.Context())
}
