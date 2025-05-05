package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jayjaytrn/gophkeeper/internal/auth"
	"github.com/jayjaytrn/gophkeeper/internal/middleware"
	"github.com/jayjaytrn/gophkeeper/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockStorage struct {
	mock.Mock
}

func (m *mockStorage) CreateUser(ctx context.Context, req types.CreateUserRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *mockStorage) GetUUIDByHash(ctx context.Context, pass string) (string, error) {
	args := m.Called(ctx, pass)
	return args.String(0), args.Error(1)
}

func (m *mockStorage) GetAllData(ctx context.Context, userID string) ([]types.SensitiveData, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]types.SensitiveData), args.Error(1)
}

func (m *mockStorage) GetData(ctx context.Context, id int64) (*types.SensitiveData, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.SensitiveData), args.Error(1)
}

func (m *mockStorage) CreateData(ctx context.Context, data *types.SensitiveData) (int64, error) {
	args := m.Called(ctx, data)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockStorage) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestHandler_Register(t *testing.T) {
	st := new(mockStorage)
	authM := auth.NewManager()
	h := Handler{Storage: st, AuthManager: authM}

	body := `{"login":"user","password":"pass"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	w := httptest.NewRecorder()

	st.On("CreateUser", mock.Anything, mock.Anything).Return(nil)

	h.Register(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
}

func TestHandler_Login(t *testing.T) {
	st := new(mockStorage)
	authM := auth.NewManager()
	h := Handler{Storage: st, AuthManager: authM}

	body := `{"password":"pass"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	st.On("GetUUIDByHash", mock.Anything, "pass").Return("user-id", nil)

	h.Login(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
}

func TestHandler_GetData(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	req := httptest.NewRequest("GET", "/data", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	expectedData := []types.SensitiveData{{UUID: "user-id", DataID: 1}}
	st.On("GetAllData", mock.Anything, "user-id").Return(expectedData, nil)

	h.GetData(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []types.SensitiveData
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, expectedData, resp)
}

func TestHandler_GetDataByID(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	req := httptest.NewRequest("GET", "/data/1", nil).WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	expectedData := &types.SensitiveData{UUID: "user-id", DataID: 1}
	st.On("GetData", mock.Anything, int64(1)).Return(expectedData, nil)

	h.GetDataByID(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp types.SensitiveData
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, *expectedData, resp)
}

func TestHandler_SaveData(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	body := `{"Credentials":{"Username":"user"}}`
	req := httptest.NewRequest("POST", "/data", bytes.NewReader([]byte(body))).WithContext(ctx)
	w := httptest.NewRecorder()

	st.On("CreateData", mock.Anything, mock.AnythingOfType("*types.SensitiveData")).Return(int64(1), nil)

	h.SaveData(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(1), resp["data_id"])
}

func TestGetUserIDFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	userID, err := GetUserIDFromContext(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "user-id", userID)

	ctxEmpty := context.Background()
	_, err = GetUserIDFromContext(ctxEmpty)
	assert.Error(t, err)
}

func TestHandler_Register_DuplicateUser(t *testing.T) {
	st := new(mockStorage)
	authM := auth.NewManager()
	h := Handler{Storage: st, AuthManager: authM}

	body := `{"login":"user","password":"pass"}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	w := httptest.NewRecorder()

	st.On("CreateUser", mock.Anything, mock.Anything).Return(errors.New("duplicate key"))

	h.Register(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandler_Login_InvalidCredentials(t *testing.T) {
	st := new(mockStorage)
	authM := auth.NewManager()
	h := Handler{Storage: st, AuthManager: authM}

	body := `{"password":"wrongpass"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	st.On("GetUUIDByHash", mock.Anything, "wrongpass").Return("", errors.New("invalid credentials"))

	h.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_Register_EmptyBody(t *testing.T) {
	st := new(mockStorage)
	authM := auth.NewManager()
	h := Handler{Storage: st, AuthManager: authM}

	req := httptest.NewRequest("POST", "/register", strings.NewReader(``))
	w := httptest.NewRecorder()

	h.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_Register_MissingFields(t *testing.T) {
	st := new(mockStorage)
	authM := auth.NewManager()
	h := Handler{Storage: st, AuthManager: authM}

	body := `{"login":""}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_GetData_Unauthorized(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	req := httptest.NewRequest("GET", "/data", nil)
	w := httptest.NewRecorder()

	h.GetData(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_GetDataByID_Forbidden(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	req := httptest.NewRequest("GET", "/data/1", nil).WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	st.On("GetData", mock.Anything, int64(1)).Return(&types.SensitiveData{UUID: "another-user"}, nil)

	h.GetDataByID(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandler_GetDataByID_NotFound(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "999")

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	req := httptest.NewRequest("GET", "/data/999", nil).WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	st.On("GetData", mock.Anything, int64(999)).Return(nil, errors.New("not found"))

	h.GetDataByID(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandler_GetDataByID_InvalidID(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "abc") // нечисловой ID

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	req := httptest.NewRequest("GET", "/data/abc", nil).WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	h.GetDataByID(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_SaveData_JSONDecodeError(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	body := `{invalid json}`
	req := httptest.NewRequest("POST", "/data", bytes.NewReader([]byte(body))).WithContext(ctx)
	w := httptest.NewRecorder()

	h.SaveData(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetUserIDFromContext_NotString(t *testing.T) {
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, 123)
	_, err := GetUserIDFromContext(ctx)
	assert.Error(t, err)
}

type errorWriter struct{}

func (e *errorWriter) Header() http.Header        { return http.Header{} }
func (e *errorWriter) WriteHeader(statusCode int) {}
func (e *errorWriter) Write(p []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestHandler_SaveData_JSONEncodeError(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	body := `{"Credentials":{"Username":"user"}}`
	req := httptest.NewRequest("POST", "/data", strings.NewReader(body))

	st.On("CreateData", mock.Anything, mock.Anything).Return(int64(1), nil)

	h.SaveData(&errorWriter{}, req.WithContext(ctx))
}

func TestHandler_GetDataByID_MissingID(t *testing.T) {
	st := new(mockStorage)
	h := Handler{Storage: st}

	rctx := chi.NewRouteContext()

	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "user-id")
	req := httptest.NewRequest("GET", "/data/", nil).WithContext(context.WithValue(ctx, chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()

	h.GetDataByID(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
