package auth

import (
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
	"time"
)

func TestBuildJWTStringWithNewID(t *testing.T) {
	m := NewManager()
	token, err := m.BuildJWTStringWithNewID("user-123")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGetUserIDFromJWTString_Success(t *testing.T) {
	m := NewManager()
	token, _ := m.BuildJWTStringWithNewID("user-123")

	userID, err := m.GetUserIDFromJWTString(token)
	assert.NoError(t, err)
	assert.Equal(t, "user-123", userID)
}

func TestGetUserIDFromJWTString_InvalidSignature(t *testing.T) {
	// вручную создаём токен с другим ключом
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{UserID: "user-123"})
	invalidToken, _ := token.SignedString([]byte("wrongsecret"))

	m := NewManager()
	_, err := m.GetUserIDFromJWTString(invalidToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token error")
}

func TestGetUserIDFromJWTString_BadFormat(t *testing.T) {
	m := NewManager()
	_, err := m.GetUserIDFromJWTString("not.a.valid.token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token error")
}

func TestGetUserIDFromJWTString_EmptyUserID(t *testing.T) {
	// валидный токен, но без userID
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
		UserID: "",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString([]byte(SecretKey))

	m := NewManager()
	_, err := m.GetUserIDFromJWTString(tokenStr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "userID is missing")
}

func TestGetUserIDFromJWTString_WrongAlgorithm(t *testing.T) {
	// Формируем токен вручную: заголовок с "alg": "none" (или RS256), без подписи
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := `{"UserID":"user-123"}`

	// Кодируем как base64url без паддинга
	enc := func(s string) string {
		return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(s)), "=")
	}
	tokenStr := fmt.Sprintf("%s.%s.%s", enc(header), enc(payload), "invalidsig")

	m := NewManager()
	_, err := m.GetUserIDFromJWTString(tokenStr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}
