package mylibrary

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// Jwt represents the JWT and Cognito configuration.
type Jwt struct {
	TokenString   string
	CognitoRegion string
	CognitoPoolID string
}

// Auth represents the authentication object.
type Auth struct {
	jwk               *JWK
	jwkURL            string
	cognitoRegion     string
	cognitoUserPoolID string
}

// Config represents the configuration object.
type Config struct {
	CognitoRegion     string
	CognitoUserPoolID string
}

// JWK represents the JSON Web Key object.
type JWK struct {
	Keys []struct {
		Alg string         `json:"alg"`
		E   string         `json:"e"`
		Kid string         `json:"kid"`
		Kty string         `json:"kty"`
		N   string         `json:"n"`
		Key *rsa.PublicKey `json:"-"`
	} `json:"keys"`
}

// ParseJWT parses and validates the JWT token.
func (a *Auth) ParseJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		var key *rsa.PublicKey
		for _, k := range a.jwk.Keys {
			if k.Kid == token.Header["kid"] {
				key = k.Key
			}
		}
		return key, nil
	})
	if err != nil {
		return token, err
	}
	return token, nil
}

// JWK returns the JWK object.
func (a *Auth) JWK() *JWK {
	return a.jwk
}

// JWKURL returns the JWK URL.
func (a *Auth) JWKURL() string {
	return a.jwkURL
}

// FetchAWSKeys fetches the AWS keys for Cognito.
func FetchAWSKeys(cognitoRegion, cognitoPoolID string) (*Auth, error) {
	a := &Auth{
		cognitoRegion:     cognitoPoolID,
		cognitoUserPoolID: cognitoPoolID,
	}
	a.jwkURL = fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", a.cognitoRegion, a.cognitoUserPoolID)
	err := a.CacheJWK()
	if err != nil {
		return a, err
	}
	for i, k := range a.jwk.Keys {
		a.jwk.Keys[i].Key = convertKey(k.E, k.N)
	}
	return a, nil
}

// CacheJWK caches the JWK from the URL.
func (a *Auth) CacheJWK() error {
	req, err := http.NewRequest("GET", a.jwkURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	jwk := new(JWK)
	err = json.Unmarshal(body, jwk)
	if err != nil {
		return err
	}
	a.jwk = jwk
	return nil
}

// convertKey converts the raw E and N values to an RSA public key.
func convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		panic(err)
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey
}
