package mcp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"time"
)

// HTTPHandler implements the JSON-response subset of Streamable HTTP. No SSE
// stream is advertised. The caller controls listening/TLS and request deadlines.
func (s *Server) HTTPHandler() (http.Handler, error) {
	if s.options.HTTPToken == "" {
		return nil, errors.New("HTTP transport requires explicit bearer authentication")
	}

	return http.HandlerFunc(s.serveHTTP), nil
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}

	if status, message := s.authorizeHTTP(r); status != 0 {
		http.Error(w, message, status)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		s.deleteHTTP(w, r.Header.Get("Mcp-Session-Id"))
	case http.MethodPost:
		s.postHTTP(w, r)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) postHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("Mcp-Session-Id")

	req, ok := decodeHTTP(w, r)
	if !ok {
		return
	}

	sess, id, status := s.httpSession(req, id)
	if status != 0 {
		message := "session unavailable"
		if status == http.StatusTooManyRequests {
			message = "session limit"
		}

		http.Error(w, message, status)

		return
	}

	if sess == nil {
		http.Error(w, "unknown session", 404)
		return
	}

	answer := s.dispatch(r.Context(), sess, req)
	if answer == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if req.Method == "initialize" {
		if answer.Error == nil {
			w.Header().Set("Mcp-Session-Id", id)
		} else {
			s.mu.Lock()
			delete(s.sessions, id)
			s.mu.Unlock()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encodeResponse(answer)) //nolint:gosec // G705: encodeResponse uses encoding/json with HTML escaping and the response is application/json.
}

func (s *Server) allowedOrigin(origin string) bool {
	return slices.Contains(s.options.AllowedOrigins, origin)
}

func (s *Server) httpSession(req request, id string) (*session, string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, sess := range s.sessions {
		if now.Sub(sess.created) > 15*time.Minute {
			cancelSession(sess)
			delete(s.sessions, key)
		}
	}

	sess := s.sessions[id]
	if req.Method != "initialize" || id != "" || len(req.ID) == 0 {
		return sess, id, 0
	}

	if len(s.sessions) >= 32 {
		return nil, id, http.StatusTooManyRequests
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, id, http.StatusInternalServerError
	}

	id = hex.EncodeToString(nonce[:])
	sess = newSession()
	s.sessions[id] = sess

	return sess, id, 0
}

func (s *Server) authorizeHTTP(r *http.Request) (int, string) {
	want, auth := "Bearer "+s.options.HTTPToken, r.Header.Get("Authorization")
	if len(auth) != len(want) || subtle.ConstantTimeCompare([]byte(auth), []byte(want)) != 1 {
		return http.StatusUnauthorized, "unauthorized"
	}

	if origin := r.Header.Get("Origin"); origin != "" && !s.allowedOrigin(origin) {
		return http.StatusForbidden, "origin rejected"
	}

	if version := r.Header.Get("Mcp-Protocol-Version"); version != "" && version != ProtocolVersion {
		return http.StatusBadRequest, "unsupported protocol version"
	}

	return 0, ""
}

func (s *Server) deleteHTTP(w http.ResponseWriter, id string) {
	s.mu.Lock()
	sess := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()

	if sess == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	cancelSession(sess)
	w.WriteHeader(http.StatusNoContent)
}

func cancelSession(sess *session) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	for _, cancel := range sess.pending {
		cancel()
	}
}

func decodeHTTP(w http.ResponseWriter, r *http.Request) (request, bool) {
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" || !acceptsJSON(r.Header.Get("Accept")) {
		http.Error(w, "JSON content type and Accept required", http.StatusUnsupportedMediaType)
		return request{}, false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
	if err != nil || len(body) > MaxMessageBytes {
		http.Error(w, "message limit", http.StatusRequestEntityTooLarge)
		return request{}, false
	}

	req, err := parseRequest(body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)

		x := failure(nil, -32700, "Invalid JSON-RPC message")
		_, _ = w.Write(encodeResponse(&x))

		return request{}, false
	}

	return req, true
}
