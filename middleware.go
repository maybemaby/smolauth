package smolauth

import (
	"net/http"

	"github.com/justinas/alice"
)

func AuthLoadMiddleware(manager *AuthManager) alice.Chain {

	return alice.New(
		manager.SessionManager.LoadAndSave,
	)
}

func RequireAuthMiddleware(authManager *AuthManager) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			userId := authManager.SessionManager.GetInt(r.Context(), SessionUserIdKey)

			if userId == 0 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
