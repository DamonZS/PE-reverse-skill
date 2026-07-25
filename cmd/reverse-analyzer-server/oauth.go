package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type oauthConfig struct{ ClientID, ClientSecret, AuthorizeURL, TokenURL, UserURL, Scopes string }

func (s *Server) oauth(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/auth/oauth/"), "/")
	if len(parts) == 1 && parts[0] == "exchange" {
		s.oauthExchange(w, r)
		return
	}
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	provider, action := parts[0], parts[1]
	cfg, err := oauthProvider(provider)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	redirect := strings.TrimRight(env("REVERSE_ANALYZER_PUBLIC_URL", "http://"+r.Host), "/") + "/api/auth/oauth/" + provider + "/callback"
	if action == "start" {
		state := newID()
		if err := s.storeOAuthState(state, redirect, time.Now().Add(10*time.Minute)); err != nil {
			s.auditAction(r, nil, auditRecordDescriptor{"oauth.start", "oauth", provider}, "failed", http.StatusServiceUnavailable, nil)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "OAuth state storage is unavailable"})
			return
		}
		s.auditAction(r, nil, auditRecordDescriptor{"oauth.start", "oauth", provider}, "succeeded", http.StatusFound, nil)
		q := url.Values{"client_id": {cfg.ClientID}, "redirect_uri": {redirect}, "scope": {cfg.Scopes}, "state": {state}, "response_type": {"code"}}
		http.Redirect(w, r, cfg.AuthorizeURL+"?"+q.Encode(), http.StatusFound)
		return
	}
	if action != "callback" {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	if err := s.consumeOAuthState(state, redirect, time.Now()); err != nil {
		s.auditAction(r, nil, auditRecordDescriptor{"oauth.callback", "oauth", provider}, "failed", http.StatusBadRequest, nil)
		bad(w, "invalid or expired OAuth state")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		bad(w, "missing OAuth code")
		return
	}
	identity, err := exchangeOAuth(r.Context(), provider, cfg, redirect, code)
	if err != nil {
		s.auditAction(r, nil, auditRecordDescriptor{"oauth.callback", "oauth", provider}, "failed", http.StatusBadGateway, nil)
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	exchangeCode, err := issueToken()
	if err == nil {
		err = s.storeOAuthExchangeCode(exchangeCode, identity, "analyst", time.Now().Add(2*time.Minute))
	}
	who := identityRecord(identity, "analyst", s.cfg.Workspace)
	if err != nil {
		s.auditAction(r, &who, auditRecordDescriptor{"oauth.callback", "oauth", provider}, "failed", http.StatusServiceUnavailable, nil)
		respond(w, nil, err)
		return
	}
	s.auditAction(r, &who, auditRecordDescriptor{"oauth.callback", "oauth", provider}, "succeeded", http.StatusFound, nil)
	http.Redirect(w, r, "/#oauth_code="+url.QueryEscape(exchangeCode), http.StatusFound)
}

func identityRecord(subject, role, workspace string) identity {
	return identity{Subject: subject, Role: role, Workspace: workspace, Source: "oauth"}
}

func (s *Server) oauthExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		method(w)
		return
	}
	var payload struct {
		Code string `json:"code"`
	}
	if readJSON(r, &payload) != nil || strings.TrimSpace(payload.Code) == "" {
		bad(w, "OAuth exchange code is required")
		return
	}
	token, err := s.consumeOAuthExchangeCode(payload.Code, time.Now())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "OAuth exchange code is invalid, expired, or consumed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "token_type": "Bearer"})
}

func oauthProvider(name string) (oauthConfig, error) {
	switch name {
	case "github":
		c := oauthConfig{os.Getenv("REVERSE_ANALYZER_GITHUB_CLIENT_ID"), os.Getenv("REVERSE_ANALYZER_GITHUB_CLIENT_SECRET"), "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", "https://api.github.com/user", "read:user user:email"}
		if c.ClientID == "" || c.ClientSecret == "" {
			return c, errors.New("GitHub OAuth is not configured")
		}
		return c, nil
	case "google":
		c := oauthConfig{os.Getenv("REVERSE_ANALYZER_GOOGLE_CLIENT_ID"), os.Getenv("REVERSE_ANALYZER_GOOGLE_CLIENT_SECRET"), "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://openidconnect.googleapis.com/v1/userinfo", "openid email profile"}
		if c.ClientID == "" || c.ClientSecret == "" {
			return c, errors.New("Google OAuth is not configured")
		}
		return c, nil
	default:
		return oauthConfig{}, errors.New("unsupported OAuth provider")
	}
}

func exchangeOAuth(ctx context.Context, provider string, cfg oauthConfig, redirect, code string) (string, error) {
	form := url.Values{"client_id": {cfg.ClientID}, "client_secret": {cfg.ClientSecret}, "code": {code}, "redirect_uri": {redirect}}
	if provider == "google" {
		form.Set("grant_type", "authorization_code")
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var token map[string]any
	if json.NewDecoder(res.Body).Decode(&token) != nil || res.StatusCode/100 != 2 {
		return "", fmt.Errorf("OAuth token exchange failed: %s", res.Status)
	}
	access := fmt.Sprint(token["access_token"])
	req, _ = http.NewRequestWithContext(ctx, "GET", cfg.UserURL, nil)
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	res, err = client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var user map[string]any
	if json.NewDecoder(res.Body).Decode(&user) != nil || res.StatusCode/100 != 2 {
		return "", fmt.Errorf("OAuth user lookup failed: %s", res.Status)
	}
	subject := fmt.Sprint(user["login"])
	if subject == "<nil>" || subject == "" {
		subject = fmt.Sprint(user["email"])
	}
	if subject == "<nil>" || subject == "" {
		subject = provider + ":" + fmt.Sprint(user["sub"])
	}
	return provider + ":" + subject, nil
}
