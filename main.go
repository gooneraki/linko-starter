package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"boot.dev/linko/internal/build"
	"boot.dev/linko/internal/linkoerr"
	"boot.dev/linko/internal/store"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	pkgerr "github.com/pkg/errors"
	"gopkg.in/natefinch/lumberjack.v2"
)

var sensitiveKeys = []string{"password", "key", "apikey", "secret", "pin", "creditcardno", "user"}

type closeFunc func() error

type stackTracer interface {
	error
	StackTrace() pkgerr.StackTrace
}

type multiError interface {
	error
	Unwrap() []error
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	httpPort := flag.Int("port", 8899, "port to listen on")
	dataDir := flag.String("data", "./data", "directory to store data")
	flag.Parse()

	status := run(ctx, cancel, *httpPort, *dataDir)
	cancel()
	os.Exit(status)
}

func run(ctx context.Context, cancel context.CancelFunc, httpPort int, dataDir string) int {
	logger, closeLogger, err := initializeLogger(os.Getenv("LINKO_LOG_FILE"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		return 1
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	logger = logger.With(
		slog.String("git_sha", build.GitSHA),
		slog.String("build_time", build.BuildTime),
		slog.String("env", os.Getenv("ENV")),
		slog.String("hostname", hostname),
	)
	defer func() {
		if err := closeLogger(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to close logger: %v\n", err)
		}
	}()

	st, err := store.New(dataDir, logger)
	if err != nil {
		logger.Error("failed to create store", "error", err)
		return 1
	}
	s := newServer(*st, httpPort, logger, cancel)
	var serverErr error
	go func() {
		serverErr = s.start()
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logger.Debug("Linko is shutting down")

	if err := s.shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown server", "error", err)
		return 1
	}
	if serverErr != nil {
		logger.Error("server error", "error", serverErr)
		return 1
	}
	return 0
}

func initializeLogger(logFile string) (*slog.Logger, closeFunc, error) {
	if logFile != "" {
		debugHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level:       slog.LevelDebug,
			ReplaceAttr: replaceAttr,
		})

		logger := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    1,
			MaxAge:     28,
			MaxBackups: 10,
			LocalTime:  false,
			Compress:   true,
		}

		infoHandler := slog.NewJSONHandler(logger, &slog.HandlerOptions{
			Level:       slog.LevelInfo,
			ReplaceAttr: replaceAttr,
		})

		closeFunc := func() error {
			return logger.Close()
		}

		return slog.New(slog.NewMultiHandler(debugHandler, infoHandler)),
			closeFunc,
			nil
	}
	return slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		ReplaceAttr: replaceAttr,
		NoColor:     !isatty.IsTerminal(os.Stderr.Fd()) && !isatty.IsCygwinTerminal(os.Stderr.Fd()),
	})), func() error { return nil }, nil
}

func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == "error" {
		err, ok := a.Value.Any().(error)
		if !ok {
			return a
		}
		if multiErr, ok := errors.AsType[multiError](err); ok {
			wrappedErrs := multiErr.Unwrap()
			errAttrs := make([]slog.Attr, 0, len(wrappedErrs))
			for i, wrappedErr := range wrappedErrs {
				errAttrs = append(errAttrs, slog.Attr{
					Key:   fmt.Sprintf("error_%d", i+1),
					Value: slog.GroupValue(errorAttrs(wrappedErr)...),
				})
			}
			return slog.GroupAttrs("errors", errAttrs...)
		}
		return slog.GroupAttrs("error", errorAttrs(err)...)
	}

	// Last-resort safety net: redact known-sensitive keys.
	if slices.Contains(sensitiveKeys, a.Key) {
		return slog.String(a.Key, "[REDACTED]")
	}

	// Last-resort safety net: redact passwords embedded in URL values.
	if a.Value.Kind() == slog.KindString {
		if redacted, ok := redactURLPassword(a.Value.String()); ok {
			return slog.String(a.Key, redacted)
		}
	}

	return a
}

// redactURLPassword parses s as a URL and, if it contains an embedded
// password, returns a copy of s with the password replaced by [REDACTED].
func redactURLPassword(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return "", false
	}
	password, hasPassword := u.User.Password()
	if !hasPassword {
		return "", false
	}
	// Replace just the password substring so the rest of the URL is left
	// exactly as it appeared, rather than percent-re-encoding the whole URL.
	return strings.Replace(s, password, "[REDACTED]", 1), true
}

func errorAttrs(err error) []slog.Attr {
	attrs := []slog.Attr{{
		Key:   "message",
		Value: slog.StringValue(err.Error()),
	}}
	attrs = append(attrs, linkoerr.Attrs(err)...)

	if stackErr, ok := errors.AsType[stackTracer](err); ok {
		attrs = append(attrs, slog.Attr{
			Key:   "stack_trace",
			Value: slog.StringValue(fmt.Sprintf("%+v", stackErr.StackTrace())),
		})
	}

	return attrs
}
