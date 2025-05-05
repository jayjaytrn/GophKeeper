package client

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestGetDataByID(t *testing.T) {
	expectedID := "123"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, expectedID) {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"DataID":"123","Credentials":{"Username":"user"}}`))
	}))
	defer server.Close()

	baseURL = server.URL

	GetDataByID(expectedID)
}

func TestListData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/data" {
			t.Errorf("expected /data, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"DataID":1,"Credentials":{"Username":"user1"}},{"DataID":2,"TextData":{"TextData":"note"}}]`))
	}))
	defer server.Close()

	baseURL = server.URL

	ListData()
}

func TestSaveCookies(t *testing.T) {
	resp := &http.Response{
		Request: &http.Request{URL: &url.URL{Scheme: "http", Host: "localhost:8080"}},
	}
	saveCookies(resp)
	if _, err := os.Stat(cookieFile); os.IsNotExist(err) {
		t.Error("cookie file was not created")
	}
	os.Remove(cookieFile)
}

func TestGetDataByID_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/data/42", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data_id":42,"credentials":{"username":"admin"}}`))
	}))
	defer server.Close()

	baseURL = server.URL
	GetDataByID("42")
}

func TestGetDataByID_NotFound(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	baseURL = server.URL
	GetDataByID("99")
}

func TestListData_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	baseURL = server.URL
	ListData()
}

func TestListData_WithData(t *testing.T) {
	resp := `[{"data_id":1,"credentials":{"username":"user1"}}]`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(resp))
	}))
	defer server.Close()

	baseURL = server.URL
	ListData()
}

func TestGetDataByID_RequestError(t *testing.T) {
	baseURL = "http://localhost:9999"
	GetDataByID("invalid")
}

func TestGetDataByID_BadJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{bad json}`))
	}))
	defer server.Close()

	baseURL = server.URL
	GetDataByID("badjson")
}

func TestListData_BadJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{bad}`))
	}))
	defer server.Close()

	baseURL = server.URL
	ListData()
}

func TestListData_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	baseURL = server.URL
	ListData()
}
