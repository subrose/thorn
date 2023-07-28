package logger

import (
	"os"

	"github.com/rs/zerolog/pkgerrors"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
		principalAccessKey string,
		principalDescription string,
		principalPolicies []string,
		requestedRecords []string,
		accessedRecords []string,
		fields []string,
	) error
}

type Logger struct {
	module         string
	logStackErrors bool
	zeroLogger     zerolog.Logger
}

func NewLogger(module, sink, level string, logStackTrace bool) (Logger, error) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if logStackTrace {
		// Should not be used in production as it might leak sensitive information
		// TODO: Add a guard to prevent this from being used in production
		zerolog.ErrorStackMarshaler = func(err error) interface{} {
			return pkgerrors.MarshalStack(errors.WithStack(err))
		}
	}

	var logger zerolog.Logger
	switch sink {
	case "stdout":
		logger = zerolog.New(os.Stdout)
	case "stderr":
		logger = zerolog.New(os.Stderr)
	case "console":
		logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	case "none":
		logger = zerolog.New(nil)
	default:
		panic("Invalid log sink")
	}

	switch level {
	case "debug":
		logger = logger.Level(zerolog.DebugLevel)
	case "info":
		logger = logger.Level(zerolog.InfoLevel)
	case "warn":
		logger = logger.Level(zerolog.WarnLevel)
	case "error":
		logger = logger.Level(zerolog.ErrorLevel)
	case "fatal":
		logger = logger.Level(zerolog.FatalLevel)
	case "panic":
		logger = logger.Level(zerolog.PanicLevel)
	default:
		panic("Invalid log level")
	}

	return Logger{
		logStackErrors: logStackTrace,
		module:         module,
		zeroLogger:     logger,
	}, nil
}

func (l Logger) Debug(msg string) {
	l.zeroLogger.Debug().Str("module", l.module).Msg(msg)
}

func (l Logger) Info(msg string) {
	l.zeroLogger.Info().Str("module", l.module).Msg(msg)
}

func (l Logger) Warn(msg string) {
	l.zeroLogger.Warn().Str("module", l.module).Msg(msg)
}

func (l Logger) Error(msg string, err error) {
	l.zeroLogger.Error().Str("module", l.module).Stack().Err(err).Msg(msg)
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
	l.zeroLogger.Info().
		Str("type", "system").
		Str("method", method).
		Str("path", path).
		Str("ip", ip).
		Str("user-agent", userAgent).
		Str("request-id", requestId).
		Float64("duration", dt).
		Int("status", status).
		Msg("Request")
}

func (l Logger) WriteAuditLog(
	method string,
	path string,
	ip string,
	userAgent string,
	requestId string,
	status int,
	principalAccessKey string,
	principalDescription string,
	principalPolicies []string,
	requestedRecords []string,
	accessedRecords []string,
	fields []string,
) {
	l.zeroLogger.Info().
		Str("type", "audit").
		Str("method", method).
		Str("path", path).
		Str("ip", ip).
		Str("user-agent", userAgent).
		Str("request-id", requestId).
		Int("status", status).
		Str("principal-username", principalAccessKey).
		Str("principal-description", principalDescription).
		Strs("principal-policies", principalPolicies).
		Strs("requested-records", requestedRecords).
		Strs("accessed-records", accessedRecords).
		Strs("fields", fields).
		Msg("Record Access")
}
