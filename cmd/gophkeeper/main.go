package main

import (
	"context"
	"errors"
	"github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jayjaytrn/gophkeeper/config"
	"github.com/jayjaytrn/gophkeeper/internal/auth"
	"github.com/jayjaytrn/gophkeeper/internal/handlers"
	"github.com/jayjaytrn/gophkeeper/internal/middleware"
	"github.com/jayjaytrn/gophkeeper/internal/storage"
	"github.com/jayjaytrn/gophkeeper/logging"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := logging.GetSugaredLogger()
	defer logger.Sync()

	ctx := context.Background()

	authManager := auth.NewManager()

	cfg := config.GetConfig()

	s := storage.GetStorage(cfg, logger)
	defer s.Close(ctx)

	h := handlers.Handler{
		Config:      cfg,
		Storage:     s,
		AuthManager: authManager,
	}

	r := initRouter(h, authManager, logger)

	server := &http.Server{
		Addr:    cfg.ServerAddress,
		Handler: r,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		logger.Infow("starting server", "address", cfg.ServerAddress, "https", cfg.EnableHTTPS)

		var err error
		if cfg.EnableHTTPS {
			if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
				logger.Infow("serving with TLS certificate and key from config",
					"cert_path", cfg.TLSCertPath,
					"key_path", cfg.TLSKeyPath,
				)
				err = server.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
			} else {
				logger.Infow("serving with autocert (Let's Encrypt)")
				manager := &autocert.Manager{
					Cache:      autocert.DirCache("cache-dir"),
					Prompt:     autocert.AcceptTOS,
					HostPolicy: autocert.HostWhitelist("mysite.ru", "www.mysite.ru"),
				}
				server.TLSConfig = manager.TLSConfig()
				err = server.ListenAndServeTLS("", "")
			}
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalw("server error", "error", err)
		}
	}()

	sig := <-sigChan
	logger.Infow("received shutdown signal", "signal", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Errorw("server shutdown error", "error", err)
	}

	logger.Infow("server gracefully stopped")
}

// initRouter init router
func initRouter(h handlers.Handler, authManager *auth.Manager, logger *zap.SugaredLogger) *chi.Mux {
	r := chi.NewRouter()

	r.Post(`/api/register`,
		func(w http.ResponseWriter, r *http.Request) {
			middleware.Conveyor(
				http.HandlerFunc(h.Register),
				logger,
				middleware.WithLogging,
			).ServeHTTP(w, r)
		},
	)

	r.Post(`/api/login`,
		func(w http.ResponseWriter, r *http.Request) {
			middleware.Conveyor(
				http.HandlerFunc(h.Login),
				logger,
				middleware.WithLogging,
				func(next http.Handler, _ *zap.SugaredLogger) http.Handler {
					return middleware.WithAuth(next, authManager, logger)
				},
			).ServeHTTP(w, r)
		},
	)

	r.Get(`/data`,
		func(w http.ResponseWriter, r *http.Request) {
			middleware.Conveyor(
				http.HandlerFunc(h.GetData),
				logger,
				middleware.WithLogging,
				middleware.WriteWithCompression,
				func(next http.Handler, _ *zap.SugaredLogger) http.Handler {
					return middleware.WithAuth(next, authManager, logger)
				},
			).ServeHTTP(w, r)
		},
	)

	r.Get(`/data/{id}`,
		func(w http.ResponseWriter, r *http.Request) {
			middleware.Conveyor(
				http.HandlerFunc(h.GetDataByID),
				logger,
				middleware.WithLogging,
				middleware.WriteWithCompression,
				func(next http.Handler, _ *zap.SugaredLogger) http.Handler {
					return middleware.WithAuth(next, authManager, logger)
				},
			).ServeHTTP(w, r)
		},
	)

	r.Post(`/data`,
		func(w http.ResponseWriter, r *http.Request) {
			middleware.Conveyor(
				http.HandlerFunc(h.SaveData),
				logger,
				middleware.WithLogging,
				func(next http.Handler, _ *zap.SugaredLogger) http.Handler {
					return middleware.WithAuth(next, authManager, logger)
				},
			).ServeHTTP(w, r)
		},
	)

	return r
}
