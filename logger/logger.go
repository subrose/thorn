package logger

import (
	"fmt"
	"os"

	"golang.org/x/exp/slog"
)

type ILogger interface {
	Debug(msg string)
	Info(msg string)
	Warn(msg string)
	Error(msg string, err error)
	WriteRequestLog(
		method string,
		path string,
		ip string,
		userAgent string,
		requestId string,
		dt float64,

		status int,
	) error
	WriteAuditLog(
		method string,
		path string,
		ip string,
		userAgent string,
		requestId string,
		status int,
		principalUsername string,
		principalDescription string,
		principalPolicies []string,
		requestedRecords []string,
		accessedRecords []string,
		fields []string,
	) error
}

type Logger struct {
	module  string
	devMode bool
	logger  *slog.Logger
}

func NewLogger(module string, sink string, handlerType string, level string, devMode bool) (Logger, error) {
	var handler slog.Handler
	var output *os.File
	var logLevel slog.Level

	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		return Logger{}, fmt.Errorf("unknown level: %s", level)
	}

	switch sink {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	case "none":
		output = nil
	default:
		return Logger{}, fmt.Errorf("unknown sink: %s", sink)
	}

	switch handlerType {
	case "json":
		handler = slog.NewJSONHandler(output, &slog.HandlerOptions{AddSource: devMode, Level: logLevel})
	case "text":
		handler = slog.NewTextHandler(output, &slog.HandlerOptions{AddSource: devMode, Level: logLevel})
	default:
		return Logger{}, fmt.Errorf("unknown handler type: %s", handlerType)
	}

	logger := slog.New(handler)

	return Logger{
		module:  module,
		devMode: devMode,
		logger:  logger,
	}, nil
}

func (l Logger) Debug(msg string) {
	l.logger.Debug(msg)
}

func (l Logger) Info(msg string) {
	l.logger.Info(msg)
}

func (l Logger) Warn(msg string) {
	l.logger.Warn(msg)
}

func (l Logger) Error(msg string, err error) {
	l.logger.Error(msg)
}

func Strings(key string, values []string) slog.Attr {
	attrs := make([]slog.Attr, len(values))
	for i, value := range values {
		attrs[i] = slog.String(fmt.Sprintf("%s[%d]", key, i), value)
	}

	anyAttrs := make([]any, len(attrs))
	for i, v := range attrs {
		anyAttrs[i] = v
	}

	return slog.Group(key, anyAttrs...)
}

func (l Logger) WriteRequestLog(
	method string,
	path string,
	ip string,
	userAgent string,
	requestId string,
	dt float64,
	status int,
) {
	l.logger.Info("Request",
		slog.String("type", "system"),
		slog.String("method", method),
		slog.String("path", path),
		slog.String("ip", ip),
		slog.String("user-agent", userAgent),
		slog.String("request-id", requestId),
		slog.Float64("duration", dt),
		slog.Int("status", status),
	)
}

func (l Logger) WriteAuditLog(
	method string,
	path string,
	ip string,
	userAgent string,
	requestId string,
	status int,
	principalUsername string,
	principalDescription string,
	principalPolicies []string,
	requestedRecords []string,
	accessedRecords []string,
	fields []string,
) {
	l.logger.Info("Record Access",
		slog.String("type", "audit"),
		slog.String("method", method),
		slog.String("path", path),
		slog.String("ip", ip),
		slog.String("user-agent", userAgent),
		slog.String("request-id", requestId),
		slog.Int("status", status),
		slog.String("principal-username", principalUsername),
		slog.String("principal-description", principalDescription),
		Strings("principal-policies", principalPolicies),
		Strings("requested-records", requestedRecords),
		Strings("accessed-records", accessedRecords),
	)
}
