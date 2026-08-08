package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"boot.dev/linko/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const shortURLLen = len("http://localhost:8080/") + 6

var (
	redirectsMu sync.Mutex
	redirects   []string
)

//go:embed index.html
var indexPage string

func (s *server) handlerIndex(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "handler.index")
	defer span.End()
	w.Header().Set("Content-Type", "text/html")
	io.WriteString(w, indexPage)
}

func (s *server) handlerLogin(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "handler.login")
	defer span.End()
	w.WriteHeader(http.StatusOK)
}

func (s *server) handlerShortenLink(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracer.Start(r.Context(), "handler.shorten_link")
	defer span.End()
	user, ok := ctx.Value(UserContextKey).(string)
	if !ok || user == "" {
		httpError(ctx, w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	longURL := r.FormValue("url")
	if longURL == "" {
		httpError(ctx, w, http.StatusBadRequest, errors.New("missing url parameter"))
		return
	}
	u, err := url.Parse(longURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		httpError(ctx, w, http.StatusBadRequest, errors.New("invalid URL: must include scheme (http/https) and host"))
		return
	}
	if err := checkDestination(ctx, longURL); err != nil {
		s.logger.Info("invalid target URL", slog.Any("error", err))
		httpError(ctx, w, http.StatusBadRequest, errors.New("invalid target url: "+err.Error()))
		return
	}
	shortCode, err := s.store.Create(ctx, longURL)
	if err != nil {
		httpError(ctx, w, http.StatusInternalServerError, errors.New("failed to shorten url"))
		return
	}
	s.logger.Info("Successfully generated short code", slog.String("short_code", shortCode), slog.String("long_url", longURL))
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, shortCode)
}

func (s *server) handlerRedirect(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracer.Start(r.Context(), "handler.redirect")
	defer span.End()
	longURL, err := s.store.Lookup(ctx, r.PathValue("shortCode"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpError(ctx, w, http.StatusNotFound, errors.New("not found"))
		} else {
			s.logger.Info("failed to lookup URL", slog.String("error", err.Error()))
			httpError(ctx, w, http.StatusInternalServerError, errors.New("internal server error"))
		}
		return
	}
	_, _ = bcrypt.GenerateFromPassword([]byte(longURL), bcrypt.DefaultCost)
	if err := checkDestination(ctx, longURL); err != nil {
		httpError(ctx, w, http.StatusBadGateway, errors.New("destination unavailable"))
		return
	}

	redirectsMu.Lock()
	redirects = append(redirects, strings.Repeat(longURL, 1024))
	redirectsMu.Unlock()

	http.Redirect(w, r, longURL, http.StatusFound)
}

func (s *server) handlerListURLs(w http.ResponseWriter, r *http.Request) {
	ctx, span := tracer.Start(r.Context(), "handler.list_urls")
	defer span.End()
	codes, err := s.store.List(ctx)
	if err != nil {
		s.logger.Info("failed to list URLs", slog.Any("error", err))
		httpError(ctx, w, http.StatusInternalServerError, errors.New("failed to list urls"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(codes)
}

func (s *server) handlerStats(w http.ResponseWriter, r *http.Request) {
	_, span := tracer.Start(r.Context(), "handler.stats")
	defer span.End()
	redirectsMu.Lock()
	snapshot := redirects
	redirectsMu.Unlock()

	var bytesSaved int
	for _, u := range snapshot {
		bytesSaved += len(u) - shortURLLen
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"redirects":   len(snapshot),
		"bytes_saved": bytesSaved,
	})
}
