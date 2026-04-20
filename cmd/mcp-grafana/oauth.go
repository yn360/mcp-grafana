package main

// MCP OAuth 2.1 support for the streamable-http transport.
//
// When --oidc-issuer-url, --oidc-client-id, and --oidc-client-secret (or
// OIDC_CLIENT_SECRET) are set, the server:
//
//  1. Exposes /.well-known/oauth-protected-resource (RFC 9728) and
//     /.well-known/oauth-authorization-server (RFC 8414) so MCP clients can
//     discover the Keycloak authorization server automatically.
//
//  2. Exposes /oauth/register (RFC 7591) — a fake Dynamic Client Registration
//     endpoint that always returns the pre-registered Keycloak client
//     credentials. Claude Code calls this to get a client_id before starting
//     PKCE; no actual dynamic registration in Keycloak is needed.
//
//  3. Protects /mcp with Bearer JWT validation via Keycloak's JWKS endpoint.
//     Tokens are verified offline (signature + iss + exp) — no per-request
//     round-trip to Keycloak.
//
//  4. Forwards the validated Bearer token to Grafana via
//     GRAFANA_FORWARD_HEADERS=Authorization so Grafana re-validates it with
//     its own Keycloak integration. No Grafana service-account token needed.

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// oauthConfig holds OIDC settings for MCP Bearer token protection.
type oauthConfig struct {
	// issuerURL is the Keycloak realm URL, e.g.
	// https://heimdall.yektanet.tech/realms/Tech
	issuerURL string
	// clientID is the pre-registered Keycloak client ID, returned verbatim from
	// the fake DCR endpoint so MCP clients can start PKCE without knowing it.
	clientID string
	// clientSecret is the Keycloak client secret, also returned from the fake
	// DCR endpoint so MCP clients can authenticate at the token endpoint.
	// Falls back to OIDC_CLIENT_SECRET env var if empty.
	clientSecret string
	// baseURL is the public URL of this MCP server used as the "resource" and
	// "issuer" in the OAuth metadata responses.
	baseURL string
}

func (oc *oauthConfig) enabled() bool {
	return oc.issuerURL != "" && oc.clientID != ""
}

// resolveSecret fills clientSecret from the env var if the flag was not set.
func (oc *oauthConfig) resolveSecret() {
	if oc.clientSecret == "" {
		oc.clientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	}
}

// oidcDiscovery is the subset of the OIDC discovery document we need.
type oidcDiscovery struct {
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// discoverOIDC fetches the OIDC provider configuration from issuerURL.
func discoverOIDC(ctx context.Context, issuerURL string) (*oidcDiscovery, error) {
	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}
	var doc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode OIDC discovery document: %w", err)
	}
	return &doc, nil
}

// jwkKey is a single JWK entry from the JWKS response.
type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// fetchJWKS fetches RSA public keys from the JWKS URI, keyed by kid.
func fetchJWKS(ctx context.Context, jwksURI string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}

	var jwks struct {
		Keys []jwkKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("decode JWK modulus for kid %q: %w", k.Kid, err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("decode JWK exponent for kid %q: %w", k.Kid, err)
		}
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	return keys, nil
}

// makeJWTValidator returns a middleware that validates Bearer JWTs offline using
// Keycloak's public keys from JWKS. It checks signature, issuer, and expiry.
func makeJWTValidator(jwksKeys map[string]*rsa.PublicKey, issuerURL, resourceMetadataURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeUnauthorized(w, resourceMetadataURL, "missing_token", "Bearer token required")
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.Parse(tokenStr,
				func(t *jwt.Token) (any, error) {
					if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
						return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
					}
					kid, _ := t.Header["kid"].(string)
					key, ok := jwksKeys[kid]
					if !ok {
						return nil, fmt.Errorf("unknown key id: %q", kid)
					}
					return key, nil
				},
				jwt.WithIssuer(issuerURL),
				jwt.WithExpirationRequired(),
			)
			if err != nil || !token.Valid {
				writeUnauthorized(w, resourceMetadataURL, "invalid_token", "Token validation failed")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeUnauthorized(w http.ResponseWriter, resourceMetadataURL, errCode, errDesc string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer resource_metadata=%q, error=%q, error_description=%q`,
		resourceMetadataURL, errCode, errDesc,
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}

// protectedResourceMetadata is the RFC 9728 response served at
// /.well-known/oauth-protected-resource.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// authorizationServerMetadata is the RFC 8414 response served at
// /.well-known/oauth-authorization-server.
// We use baseURL as the issuer and include a registration_endpoint pointing to
// our own /oauth/register so MCP clients (e.g. Claude Code) can proceed with
// PKCE without requiring actual Dynamic Client Registration in Keycloak.
type authorizationServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
}

// dcrRequest is the subset of the RFC 7591 client registration request we need.
type dcrRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
}

// dcrResponse is the RFC 7591 client registration response returned by
// /oauth/register. It always returns the pre-registered Keycloak client
// credentials so MCP clients can use PKCE without knowing them in advance.
type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int      `json:"client_secret_expires_at"` // 0 = never
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	// Scope tells MCP clients which scopes to request during PKCE so the
	// resulting access token contains the claims Grafana needs (email,
	// preferred_username, resource_access.grafana.roles).
	Scope string `json:"scope"`
}

// setupOAuthHandlers registers the OAuth 2.1 discovery and registration
// endpoints on mux and returns a JWT validation middleware for /mcp.
// Returns nil middleware if OAuth is disabled (oc.enabled() == false).
func setupOAuthHandlers(ctx context.Context, mux *http.ServeMux, oc *oauthConfig) (func(http.Handler) http.Handler, error) {
	if !oc.enabled() {
		return nil, nil
	}
	oc.resolveSecret()
	if oc.clientSecret == "" {
		return nil, fmt.Errorf("OIDC is enabled but --oidc-client-secret / OIDC_CLIENT_SECRET is not set")
	}

	slog.Info("Discovering OIDC provider", "issuer", oc.issuerURL)
	doc, err := discoverOIDC(ctx, oc.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}

	jwksKeys, err := fetchJWKS(ctx, doc.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	slog.Info("Loaded JWKS keys", "count", len(jwksKeys))

	resourceMetadataURL := oc.baseURL + "/.well-known/oauth-protected-resource"
	registrationEndpoint := oc.baseURL + "/oauth/register"

	prmJSON, err := json.Marshal(protectedResourceMetadata{
		Resource:             oc.baseURL,
		AuthorizationServers: []string{oc.baseURL},
	})
	if err != nil {
		return nil, err
	}

	asmJSON, err := json.Marshal(authorizationServerMetadata{
		Issuer:                        oc.baseURL,
		AuthorizationEndpoint:         doc.AuthorizationEndpoint,
		TokenEndpoint:                 doc.TokenEndpoint,
		JWKSURI:                       doc.JWKSURI,
		RegistrationEndpoint:          registrationEndpoint,
		ResponseTypesSupported:        doc.ResponseTypesSupported,
		CodeChallengeMethodsSupported: doc.CodeChallengeMethodsSupported,
		ScopesSupported:               []string{"openid", "email", "profile", "roles"},
	})
	if err != nil {
		return nil, err
	}

	// RFC 9728: Protected Resource Metadata.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(prmJSON)
	})

	// RFC 8414: Authorization Server Metadata.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(asmJSON)
	})

	// RFC 7591: fake Dynamic Client Registration.
	// Always returns the pre-registered Keycloak client credentials.
	// redirect_uris from the request are echoed back — Claude Code validates
	// their presence in the response.
	dcrClientID := oc.clientID
	dcrClientSecret := oc.clientSecret
	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var req dcrRequest
		// Best-effort parse — if body is missing or malformed we still respond.
		_ = json.NewDecoder(r.Body).Decode(&req)

		resp := dcrResponse{
			ClientID:                dcrClientID,
			ClientSecret:            dcrClientSecret,
			ClientIDIssuedAt:        time.Now().Unix(),
			ClientSecretExpiresAt:   0,
			RedirectURIs:            req.RedirectURIs,
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "client_secret_basic",
			Scope:                   "openid email profile roles",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})

	middleware := makeJWTValidator(jwksKeys, oc.issuerURL, resourceMetadataURL)

	slog.Info("MCP OAuth 2.1 enabled",
		"issuer", oc.issuerURL,
		"client-id", oc.clientID,
		"jwks-uri", doc.JWKSURI,
	)
	return middleware, nil
}
