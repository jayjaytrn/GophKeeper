package logging

import "go.uber.org/zap"

// GetSugaredLogger initializes and returns a SugaredLogger instance.
// The SugaredLogger provides a more flexible API for logging, supporting structured logging with key-value pairs.
// It uses a development logger configuration by default, which is useful for debugging.
func GetSugaredLogger() *zap.SugaredLogger {
	// Create a new development logger.
	logger, err := zap.NewDevelopment()
	if err != nil {
		// If the logger cannot be initialized, panic.
		panic("cannot initialize zap")
	}

	// Return the sugared logger for easy structured logging.
	sl := logger.Sugar()

	return sl
}
