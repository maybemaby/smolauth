package smolauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

const OAUTH_STATE_SESSION_KEY = "oauth_state"
const OAUTH_VERIFIER_SESSION_KEY = "oauth_verifier"

var ErrStateMismatch = errors.New("state mismatch")

// GenerateState generates a random state string, base64 urlencoded with a length of 64 bytes
func GenerateState() (string, error) {
	nonceBytes := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, nonceBytes)

	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

// ValidateState checks if the state in the query matches the state in the cookie,
// returns ErrStateMismatch if the states do not match
// Assumes the state cookie name is OAUTH_STATE_SESSION_KEY
func ValidateState(r *http.Request) error {
	state := r.URL.Query().Get("state")

	if state == "" {
		return errors.New("missing state")
	}

	cookie, err := r.Cookie(OAUTH_STATE_SESSION_KEY)

	if err != nil {
		return err
	}

	if cookie.Value != state {
		return ErrStateMismatch
	}

	return nil
}

type OAuthProvider interface {
	// HandleAuth should handle generating and redirecting to the OAuth provider's authorization URL
	HandleAuth(w http.ResponseWriter, r *http.Request)
	// HandleCallback should handle the callback from the OAuth provider, exchange the code for tokens, and updating the database
	HandleCallback(authManager *AuthManager) http.HandlerFunc
}

// Google
type GoogleProvider struct {
	config          *oauth2.Config
	postCallbackUrl string
}

func NewGoogleProvider(clientId, clientSecret, redirectUrl string, postCallbackUrl string, extraScopes []string) *GoogleProvider {

	scopes := append([]string{"profile", "email", "openid"}, extraScopes...)

	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  redirectUrl,
			Endpoint:     google.Endpoint,
			Scopes:       scopes,
		},
		postCallbackUrl: postCallbackUrl,
	}
}

func (gp *GoogleProvider) HandleAuth(w http.ResponseWriter, r *http.Request) {
	state, err := GenerateState()
	verifier := oauth2.GenerateVerifier()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     OAUTH_STATE_SESSION_KEY,
		Value:    state,
		MaxAge:   60 * 5,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     OAUTH_VERIFIER_SESSION_KEY,
		Value:    verifier,
		MaxAge:   60 * 5,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	url := gp.config.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GoogleToken is a custom struct to hold the oidc token response
// ExpiresIn remaining lifetime of the token in seconds
type GoogleToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	IDToken      string    `json:"id_token"`
	ExpiresIn    *int      `json:"expires_in,omitempty"`
	Scope        string    `json:"scope"`
}

type googleUserInfo struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	FamilyName    string `json:"family_name"`
	GivenName     string `json:"given_name"`
	Picture       string `json:"picture"`
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	Locale        string `json:"locale"`
}

func newGoogleToken(tok *oauth2.Token) *GoogleToken {

	tokExpiresIn := tok.Extra("expires_in")

	if tokExpiresIn != nil {
		expiresIn := int(math.Round(tokExpiresIn.(float64)))

		return &GoogleToken{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			Expiry:       tok.Expiry,
			IDToken:      tok.Extra("id_token").(string),
			ExpiresIn:    &expiresIn,
			Scope:        tok.Extra("scope").(string),
		}
	}

	return &GoogleToken{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
		IDToken:      tok.Extra("id_token").(string),
		ExpiresIn:    nil,
		Scope:        tok.Extra("scope").(string),
	}
}

// googleExchange exchanges the code for tokens and gets user info from Google
func (gp *GoogleProvider) googleExchange(ctx context.Context, code string, verifier string) (*GoogleToken, *googleUserInfo, error) {
	tok, err := gp.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))

	if err != nil {
		return nil, nil, err
	}

	googleToken := newGoogleToken(tok)

	client := gp.config.Client(ctx, tok)

	userInfo, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")

	if err != nil {
		return nil, nil, err
	}

	defer userInfo.Body.Close()

	var userJson googleUserInfo
	json.NewDecoder(userInfo.Body).Decode(&userJson)

	return googleToken, &userJson, nil
}

func (gp *GoogleProvider) HandleCallback(authManager *AuthManager) http.HandlerFunc {
	loggerEnabled := authManager.Logger != nil

	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		stateErr := ValidateState(r)

		if stateErr != nil {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		verifierCookie, err := r.Cookie(OAUTH_VERIFIER_SESSION_KEY)

		if err != nil {
			http.Error(w, "missing verifier", http.StatusBadRequest)
			return
		}

		verifier := verifierCookie.Value

		if verifier == "" {
			http.Error(w, "missing verifier", http.StatusBadRequest)
			return
		}

		token, userInfo, err := gp.googleExchange(r.Context(), code, verifier)

		if err != nil {
			if loggerEnabled {
				authManager.Logger.Debug("smolauth: error exchanging code for token", slog.String("error", err.Error()))
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := authManager.getUserAccount(userInfo.Email, "google")

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {

				if loggerEnabled {
					authManager.Logger.Debug("smolauth: creating new user from google login")
				}

				// User does not exist, create user
				id, err := authManager.insertUserAccount(UserAccount{
					Email:                userInfo.Email,
					Provider:             "google",
					ProviderId:           userInfo.Sub,
					AccessToken:          token.AccessToken,
					RefreshToken:         token.RefreshToken,
					AccessTokenExpiresAt: token.Expiry,
				})

				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				err = authManager.Login(r, SessionData{UserId: id})

				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, gp.postCallbackUrl, http.StatusTemporaryRedirect)
				return
			} else {
				// Just fail if there's an error besides not finding the user
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		if user.ProviderId == nil || user.Provider == nil {
			if loggerEnabled {
				authManager.Logger.Debug("smolauth: no account found for user", slog.Int("userId", user.Id))
			}

			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if loggerEnabled {
			authManager.Logger.Debug("smolauth: updating user google tokens", slog.Int("userId", user.Id))
		}

		err = authManager.updateAccountTokens(user.Id, *user.Provider, *user.ProviderId, updateAccountTokenData{
			AccessToken:       token.AccessToken,
			RefreshToken:      token.RefreshToken,
			AccessTokenExpiry: sql.NullTime{Time: token.Expiry, Valid: true},
		})

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = authManager.Login(r, SessionData{UserId: user.Id})

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, gp.postCallbackUrl, http.StatusTemporaryRedirect)
	}
}

// GitHub
type GithubProvider struct {
	config          *oauth2.Config
	postCallbackUrl string
}

func NewGithubProvider(clientId, clientSecret, redirectUrl string, postCallbackUrl string, extraScopes []string) *GithubProvider {

	scopes := append([]string{"user:email", "read:user", "user"}, extraScopes...)

	return &GithubProvider{
		config: &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  redirectUrl,
			Endpoint:     github.Endpoint,
			Scopes:       scopes,
		},
		postCallbackUrl: postCallbackUrl,
	}
}

func (ghp *GithubProvider) HandleAuth(w http.ResponseWriter, r *http.Request) {
	state, err := GenerateState()
	verifier := oauth2.GenerateVerifier()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     OAUTH_STATE_SESSION_KEY,
		Value:    state,
		MaxAge:   60 * 5,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     OAUTH_VERIFIER_SESSION_KEY,
		Value:    verifier,
		MaxAge:   60 * 5,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	url := ghp.config.AuthCodeURL(state, oauth2.AccessTypeOnline)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

type githubUserInfo struct {
	Id        int    `json:"id"`
	Login     string `json:"login"`
	AvatarUrl string `json:"avatar_url"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Company   string `json:"company"`
	Bio       string `json:"bio"`
	Location  string `json:"location"`
	HtmlUrl   string `json:"html_url"`
}

type githubUserEmailResponse struct {
	Email      string `json:"email"`
	Verified   bool   `json:"verified"`
	Primary    bool   `json:"primary"`
	Visibility string `json:"visibility"`
}

func (ghp *GithubProvider) HandleCallback(authManager *AuthManager) http.HandlerFunc {
	loggerEnabled := authManager.Logger != nil
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		stateErr := ValidateState(r)

		if stateErr != nil {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		tok, err := ghp.config.Exchange(r.Context(), code)

		if err != nil {

			if loggerEnabled {
				authManager.Logger.Debug("smolauth: error exchanging code for token", slog.String("error", err.Error()))
			}

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		client := ghp.config.Client(r.Context(), tok)

		userInfo, err := client.Get("https://api.github.com/user")

		if err != nil {

			if loggerEnabled {
				authManager.Logger.Debug("smolauth: error getting user info", slog.String("error", err.Error()))
			}

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		defer userInfo.Body.Close()

		var userJson githubUserInfo
		json.NewDecoder(userInfo.Body).Decode(&userJson)
		var email string
		var emailRes []githubUserEmailResponse

		// Github users can set email to private, must get email from a separate endpoint
		if userJson.Email == "" {

			emailInfo, err := client.Get("https://api.github.com/user/emails")

			if err != nil {

				if loggerEnabled {
					authManager.Logger.Debug("smolauth: error getting user emails", slog.String("error", err.Error()))
				}

				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			defer emailInfo.Body.Close()

			err = json.NewDecoder(emailInfo.Body).Decode(&emailRes)

			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}

			email = emailRes[0].Email
		} else {
			email = userJson.Email
		}

		user, err := authManager.getUserAccount(email, "github")

		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {

				if loggerEnabled {
					authManager.Logger.Debug("smolauth: creating new user from github login")
				}

				id, err := authManager.insertUserAccount(UserAccount{
					Email:    email,
					Provider: "github",
					// Github user id is an integer
					ProviderId:   strconv.Itoa(userJson.Id),
					AccessToken:  tok.AccessToken,
					RefreshToken: tok.RefreshToken,
					// Github tokens do not expire, set to 5 years in the future
					AccessTokenExpiresAt: time.Now().Add(time.Hour * 24 * 365 * 5),
				})

				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				err = authManager.Login(r, SessionData{UserId: id})

				if err != nil {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, ghp.postCallbackUrl, http.StatusTemporaryRedirect)
				return
			}
		}

		if user.ProviderId == nil || user.Provider == nil {
			if loggerEnabled {
				authManager.Logger.Debug("smolauth: no account found for user", slog.Int("userId", user.Id))
			}

			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if loggerEnabled {
			authManager.Logger.Debug("smolauth: updating user github tokens", slog.Int("userId", user.Id))
		}

		err = authManager.updateAccountTokens(user.Id, *user.Provider, *user.ProviderId, updateAccountTokenData{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			// Github tokens do not expire, set to 5 years in the future
			AccessTokenExpiry: sql.NullTime{Time: time.Now().Add(time.Hour * 24 * 365 * 5), Valid: true},
		})

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = authManager.Login(r, SessionData{UserId: user.Id})

		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, ghp.postCallbackUrl, http.StatusTemporaryRedirect)
	}
}

// Facebook

// AuthManager methods

func (am *AuthManager) HandleOAuth(name string) http.HandlerFunc {
	provider, ok := am.providers[name]

	if !ok {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Provider not found", http.StatusNotFound)
		}
	}

	return provider.HandleAuth
}

func (am *AuthManager) HandleOAuthCallback(name string) http.HandlerFunc {
	provider, ok := am.providers[name]

	if !ok {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Provider not found", http.StatusNotFound)
		}
	}

	return provider.HandleCallback(am)
}

func (am *AuthManager) WithGoogle(provider *GoogleProvider) {
	am.providers["google"] = provider
}

func (am *AuthManager) WithGithub(provider *GithubProvider) {
	am.providers["github"] = provider
}

// Add generic OAuth provider not covered by the built-in providers
func (am *AuthManager) WithProvider(name string, provider OAuthProvider) {
	am.providers[name] = provider
}

type existingUserAccount struct {
	Id         int
	Email      string
	Provider   *string
	ProviderId *string `db:"provider_id"`
}

const getUserAccountSqlite = `
SELECT u.id, u.email, a.provider, a.provider_id from users u
LEFT JOIN accounts as a ON u.id = a.user_id
WHERE u.email = ?
`

const getUserAccountPostgres = `
SELECT u.id, u.email, a.provider, a.provider_id from users u
LEFT JOIN accounts as a ON u.id = a.user_id
WHERE u.email = $1
`

func (am *AuthManager) getUserAccount(email string, provider string) (existingUserAccount, error) {
	var users []existingUserAccount
	var err error
	var stmt *sql.Stmt

	if am.databaseType == "sqlite" {
		stmt, err = am.db.Prepare(getUserAccountSqlite)
	} else if am.databaseType == "postgres" {
		stmt, err = am.db.Prepare(getUserAccountPostgres)
	}

	if err != nil {
		return existingUserAccount{}, err
	}

	defer stmt.Close()

	rows, err := stmt.Query(email)

	if err != nil {
		return existingUserAccount{}, err
	}

	defer rows.Close()

	for rows.Next() {
		var u existingUserAccount
		err = rows.Scan(&u.Id, &u.Email, &u.Provider, &u.ProviderId)

		if err != nil {
			return existingUserAccount{}, err
		}

		users = append(users, u)
	}

	idx := slices.IndexFunc(users, func(u existingUserAccount) bool {
		return u.Provider != nil && *u.Provider == provider
	})

	if idx == -1 {
		return users[0], nil
	}

	return users[idx], err
}

type updateAccountTokenData struct {
	AccessToken       string
	RefreshToken      string
	AccessTokenExpiry sql.NullTime
}

const updateAccountTokenSqlite = `
UPDATE accounts SET access_token = ?, refresh_token = ?, access_token_expires_at = ? WHERE user_id = ? AND provider = ? AND provider_id = ?
`
const updateAccountTokensPg = `
UPDATE accounts SET access_token = $1, refresh_token = $2, access_token_expires_at = $3 WHERE user_id = $4 AND provider = $5 AND provider_id = $6
`

func (am *AuthManager) updateAccountTokens(userId int, provider, providerId string, data updateAccountTokenData) error {
	var stmt *sql.Stmt
	var err error

	if am.databaseType == "sqlite" {
		stmt, err = am.db.Prepare(updateAccountTokenSqlite)
	} else {
		stmt, err = am.db.Prepare(updateAccountTokensPg)
	}

	if err != nil {
		return err
	}

	defer stmt.Close()

	_, err = stmt.Exec(data.AccessToken, data.RefreshToken, data.AccessTokenExpiry, userId, provider, providerId)

	return err
}
