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
	"strings"
	"time"

	"github.com/skarm/scout/internal/netpolicy"
)

const (
	headerMCPSessionID       = "Mcp-Session-Id"
	headerMCPProtocolVersion = "Mcp-Protocol-Version"
	headerWWWAuthenticate    = "WWW-Authenticate"
	headerOrigin             = "Origin"
	headerAllow              = "Allow"
	httpEndpoint             = "/mcp"
	httpAllowedMethods       = "POST, DELETE"

	maxHTTPSessions     = 32
	httpSessionLifetime = 15 * time.Minute
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
	if r.URL.Path != httpEndpoint {
		http.NotFound(w, r)
		return
	}

	if status, message := s.authorizeHTTP(r); status != 0 {
		if status == http.StatusUnauthorized {
			w.Header().Set(headerWWWAuthenticate, `Bearer realm="scout"`)
		}

		http.Error(w, message, status)

		return
	}

	id := r.Header.Get(headerMCPSessionID)
	switch r.Method {
	case http.MethodDelete:
		s.deleteHTTP(w, id)
		return
	case http.MethodPost:
		s.postHTTP(w, r, id)
		return
	case http.MethodGet:
		if id != "" && s.lookupHTTPSession(id) == nil {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
	}

	w.Header().Set(headerAllow, httpAllowedMethods)
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (s *Server) postHTTP(w http.ResponseWriter, r *http.Request, id string) {
	var sess *session
	if id != "" {
		sess = s.lookupHTTPSession(id)
		if sess == nil {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
	}

	req, ok := decodeHTTP(w, r)
	if !ok {
		return
	}

	created := sess == nil
	if created {
		if req.Method != methodInitialize || len(req.ID) == 0 {
			http.Error(w, "session ID required", http.StatusBadRequest)
			return
		}

		var status int

		sess, id, status = s.createHTTPSession()
		if status != 0 {
			message := "session unavailable"
			if status == http.StatusTooManyRequests {
				message = "session limit"
			}

			http.Error(w, message, status)

			return
		}
	}

	answer := s.dispatch(r.Context(), sess, req)
	if answer == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if created {
		if answer.Error == nil {
			w.Header().Set(headerMCPSessionID, id)
		} else {
			s.mu.Lock()
			delete(s.sessions, id)
			s.mu.Unlock()
			cancelSession(sess)
		}
	}

	w.Header().Set(netpolicy.HeaderContentType, netpolicy.JSONMediaType)
	_, _ = w.Write(encodeResponse(answer))
}

func (s *Server) allowedOrigin(origin string) bool {
	return slices.Contains(s.options.AllowedOrigins, origin)
}

func (s *Server) lookupHTTPSession(id string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessions(time.Now())

	return s.sessions[id]
}

func (s *Server) createHTTPSession() (*session, string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireSessions(time.Now())

	if len(s.sessions) >= maxHTTPSessions {
		return nil, "", http.StatusTooManyRequests
	}

	const sessionNonceBytes = 24

	var nonce [sessionNonceBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", http.StatusInternalServerError
	}

	id := hex.EncodeToString(nonce[:])
	sess := newSession()
	s.sessions[id] = sess

	return sess, id, 0
}

func (s *Server) authorizeHTTP(r *http.Request) (int, string) {
	scheme, token, ok := strings.Cut(r.Header.Get(netpolicy.HeaderAuthorization), " ")

	token = strings.TrimLeft(token, " ")
	if !ok || !strings.EqualFold(scheme, netpolicy.BearerScheme) || subtle.ConstantTimeCompare([]byte(token), []byte(s.options.HTTPToken)) != 1 {
		return http.StatusUnauthorized, "unauthorized"
	}

	if origin := r.Header.Get(headerOrigin); origin != "" && !s.allowedOrigin(origin) {
		return http.StatusForbidden, "origin rejected"
	}

	if version := r.Header.Get(headerMCPProtocolVersion); version != "" && version != ProtocolVersion {
		return http.StatusBadRequest, "unsupported protocol version"
	}

	return 0, ""
}

func (s *Server) deleteHTTP(w http.ResponseWriter, id string) {
	if id == "" {
		http.Error(w, "session ID required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.expireSessions(time.Now())
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

// expireSessions applies the same deadline to every session lookup. The caller holds s.mu.
func (s *Server) expireSessions(now time.Time) {
	for id, sess := range s.sessions {
		if now.Sub(sess.created) >= httpSessionLifetime {
			delete(s.sessions, id)
			cancelSession(sess)
		}
	}
}

func cancelSession(sess *session) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	sess.closed = true
	sess.ready = false

	for _, cancel := range sess.pending {
		cancel()
	}
}

func decodeHTTP(w http.ResponseWriter, r *http.Request) (request, bool) {
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get(netpolicy.HeaderContentType))
	if mediaErr != nil || mediaType != netpolicy.JSONMediaType {
		http.Error(w, "JSON content type required", http.StatusUnsupportedMediaType)
		return request{}, false
	}

	if !acceptsJSON(strings.Join(r.Header.Values(netpolicy.HeaderAccept), ",")) {
		http.Error(w, "Accept must allow application/json", http.StatusNotAcceptable)
		return request{}, false
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxMessageBytes+1))
	if len(body) > MaxMessageBytes {
		http.Error(w, "message limit", http.StatusRequestEntityTooLarge)
		return request{}, false
	}

	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return request{}, false
	}

	req, err := parseRequest(body)
	if err != nil {
		w.Header().Set(netpolicy.HeaderContentType, netpolicy.JSONMediaType)
		w.WriteHeader(http.StatusBadRequest)

		if x := requestFailure(req, err); x != nil {
			_, _ = w.Write(encodeResponse(x))
		}

		return request{}, false
	}

	return req, true
}
