package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jayjaytrn/gophkeeper/config"
	"github.com/jayjaytrn/gophkeeper/internal/auth"
	"github.com/jayjaytrn/gophkeeper/internal/middleware"
	"github.com/jayjaytrn/gophkeeper/internal/storage"
	"github.com/jayjaytrn/gophkeeper/internal/types"
	"net/http"
	"strconv"
	"strings"
)

// Handler represents the main HTTP handler.
type Handler struct {
	Storage     storage.DBStorage
	Config      *config.Config
	AuthManager *auth.Manager
}

// Register регистрирует нового пользователя.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req types.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Login == "" || req.Password == "" {
		http.Error(w, "login and password required", http.StatusBadRequest)
		return
	}

	req.UUID = uuid.New().String()

	if err := h.Storage.CreateUser(r.Context(), req); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			http.Error(w, "user already registered", http.StatusConflict)
			return
		}
		http.Error(w, "failed to create user", http.StatusInternalServerError)
		return
	}

	jwt, err := h.AuthManager.BuildJWTStringWithNewID(req.UUID)
	if err != nil {
		http.Error(w, "could not create token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "Authorization",
		Value:    jwt,
		Path:     "/",
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusCreated)
}

// Login аутентифицирует пользователя по паролю.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req types.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, "password required", http.StatusBadRequest)
		return
	}

	userID, err := h.Storage.GetUUIDByHash(r.Context(), req.Password)
	if err != nil {
		http.Error(w, "invalid login or password", http.StatusUnauthorized)
		return
	}

	jwt, err := h.AuthManager.BuildJWTStringWithNewID(userID)
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "Authorization",
		Value:    jwt,
		Path:     "/",
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
}

// GetData get data
func (h *Handler) GetData(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	entries, err := h.Storage.GetAllData(r.Context(), userID)
	if err != nil {
		http.Error(w, "failed to get data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// GetDataByID get data by ID
func (h *Handler) GetDataByID(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		http.Error(w, "missing data ID", http.StatusBadRequest)
		return
	}

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid data ID", http.StatusBadRequest)
		return
	}

	entry, err := h.Storage.GetData(r.Context(), id)
	if err != nil {
		http.Error(w, "data not found", http.StatusNotFound)
		return
	}

	if entry.UUID != userID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

// SaveData save data
func (h *Handler) SaveData(w http.ResponseWriter, r *http.Request) {
	userID, err := GetUserIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req types.ClientSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	entry := &types.SensitiveData{
		UUID:        userID,
		Credentials: req.Credentials,
		TextData:    req.TextData,
		BinaryData:  req.BinaryData,
		CardDetails: req.CardDetails,
	}

	dataID, err := h.Storage.CreateData(r.Context(), entry)
	if err != nil {
		http.Error(w, "failed to save data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"data_id": dataID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		http.Error(w, "failed to save data: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func GetUserIDFromContext(ctx context.Context) (string, error) {
	val := ctx.Value(middleware.UserIDKey)
	if userID, ok := val.(string); ok && userID != "" {
		return userID, nil
	}
	return "", fmt.Errorf("user ID not found in context")
}
