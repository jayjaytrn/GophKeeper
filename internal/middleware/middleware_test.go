package middleware

import (
	"bytes"
	"compress/gzip"
	"github.com/jayjaytrn/gophkeeper/internal/auth"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteWithCompression_Enabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello"))
	})

	obs, _ := observer.New(zapcore.InfoLevel)
	sugar := zap.New(obs).Sugar()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")

	rr := httptest.NewRecorder()
	WriteWithCompression(handler, sugar).ServeHTTP(rr, req)

	assert.Equal(t, "gzip", rr.Header().Get("Content-Encoding"))

	reader, err := gzip.NewReader(rr.Body)
	assert.NoError(t, err)
	uncompressed, _ := io.ReadAll(reader)
	assert.Equal(t, "Hello", string(uncompressed))
}

func TestWriteWithCompression_Disabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Raw"))
	})

	sugar := zap.NewNop().Sugar()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()

	WriteWithCompression(handler, sugar).ServeHTTP(rr, req)

	assert.Equal(t, "", rr.Header().Get("Content-Encoding"))
	assert.Equal(t, "Raw", rr.Body.String())
}

func TestReadWithCompression_Enabled(t *testing.T) {
	var received string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		received = string(data)
	})

	sugar := zap.NewNop().Sugar()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("Compressed"))
	gz.Close()

	req := httptest.NewRequest("POST", "/", &buf)
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()

	ReadWithCompression(handler, sugar).ServeHTTP(rr, req)
	assert.Equal(t, "Compressed", received)
}

func TestReadWithCompression_Disabled(t *testing.T) {
	var received string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
	})

	sugar := zap.NewNop().Sugar()
	req := httptest.NewRequest("POST", "/", strings.NewReader("plain"))
	rr := httptest.NewRecorder()

	ReadWithCompression(handler, sugar).ServeHTTP(rr, req)
	assert.Equal(t, "plain", received)
}

func TestWithLogging(t *testing.T) {
	obs, logs := observer.New(zapcore.InfoLevel)
	sugar := zap.New(obs).Sugar()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("I'm a teapot"))
	})

	req := httptest.NewRequest("GET", "/log", nil)
	rr := httptest.NewRecorder()

	WithLogging(handler, sugar).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTeapot, rr.Code)
	assert.True(t, strings.Contains(logs.All()[0].Message, "uri"))
}

func TestWithAuth_Success(t *testing.T) {
	manager := auth.NewManager()
	sugar := zap.NewNop().Sugar()

	validJWT, _ := manager.BuildJWTStringWithNewID("user-123")

	var called bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.Context().Value(UserIDKey)
		called = true
		assert.Equal(t, "user-123", val)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: validJWT})
	rr := httptest.NewRecorder()

	WithAuth(handler, manager, sugar).ServeHTTP(rr, req)
	assert.True(t, called)
}

func TestWithAuth_MissingCookie(t *testing.T) {
	manager := auth.NewManager()
	sugar := zap.NewNop().Sugar()

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	WithAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}), manager, sugar).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestWithAuth_InvalidJWT(t *testing.T) {
	manager := auth.NewManager()
	sugar := zap.NewNop().Sugar()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: "bad.jwt.token"})
	rr := httptest.NewRecorder()

	WithAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}), manager, sugar).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestConveyor_Order(t *testing.T) {
	var trace []string

	m1 := func(h http.Handler, _ *zap.SugaredLogger) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trace = append(trace, "m1")
			h.ServeHTTP(w, r)
		})
	}
	m2 := func(h http.Handler, _ *zap.SugaredLogger) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trace = append(trace, "m2")
			h.ServeHTTP(w, r)
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace = append(trace, "handler")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	sugar := zap.NewNop().Sugar()

	Conveyor(handler, sugar, m1, m2).ServeHTTP(rr, req)

	assert.Equal(t, []string{"m2", "m1", "handler"}, trace)
}
