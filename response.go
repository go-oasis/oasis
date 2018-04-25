package oasis

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Responder represents a common interface to
// cache an http response.
//
// Should any problem happen, a Responder is
// expected to either:
// 1. do nothing to the http.ResponseWriter and
//    return an error that implements ResponderError
//    interface; or
// 2. handle the http output itself before returning
//    other types of error.
type Responder interface {
	// ResponseTo writes a response to a given http.ResponseWriter.
	ResponseTo(http.ResponseWriter) error
}

// ResponderError represents an error
// with proper http response code and
// user understandable message.
//
// It is supposed to be returned by
// Responder that defer their error
// displaying to default handles.
type ResponderError interface {

	// Code returns the HTTP response code
	// for the supposed displaying page.
	Code() int

	// Message returns the user understandable
	// message about the error.
	Message() string

	// ResponderError should implement the error interface
	error
}

// ResponseCache is a simple implementation of
// Responder interface.
type ResponseCache struct {
	Code        int
	HeaderCache http.Header
	Body        io.Reader
}

// ResponseTo implements Responder interface
func (rc *ResponseCache) ResponseTo(w http.ResponseWriter) (err error) {
	// copy header
	for key, values := range rc.HeaderCache {
		for i := range values {
			w.Header().Add(key, values[i])
		}
	}

	// write header with response code
	w.WriteHeader(rc.Code)
	if rc.Body != nil {
		_, err = io.Copy(w, rc.Body)
	}
	return
}

// RedirectResponse is used for final success or error
// response to any Authorization Request. Except if the
// error need extra prompt to user (see RFC6749 section
// 4.1.2.1 and 4.2.2.1).
//
// In RFC, the response can either be:
// 1. an Authorization Response (for Authorization Grant), or
// 2. a Token Response (for Implicit Grant).
// 3. an Error Response.
//
// In any case, the response is a URL redirection.
type RedirectResponse struct {

	// HeaderCache stores the response http header
	HeaderCache http.Header

	// RedirectURI is the base redirection uri as specified
	// by request or by client's default.
	RedirectURI string

	// Query is the additional key-values to be
	// appended to the query parameters.
	Query url.Values

	// Fragment is the key-values to be appended
	// to the redirect uri, encoded as
	// "application/x-www-form-urlencoded" format,
	// as the fragment component (i.e. "#abcd"
	// at the end of URI).
	Fragment url.Values
}

// ResponseTo implements Responder interface
func (rr *RedirectResponse) ResponseTo(w http.ResponseWriter) (err error) {

	// copy header
	for key, values := range rr.HeaderCache {
		for i := range values {
			w.Header().Add(key, values[i])
		}
	}

	// parse final redirect uri
	if rr.RedirectURI == "" {
		err = fmt.Errorf("redirect_uri not set")
		return
	}
	redirectURI, err := url.Parse(rr.RedirectURI)
	if err != nil {
		err = fmt.Errorf("redirect_uri is misformed. %s", err.Error())
		return
	}
	if redirectURI.Scheme == "" || redirectURI.Host == "" {
		err = fmt.Errorf(`redirect_uri is misformed. expected a full URI but got "%s"`, rr.RedirectURI)
		return
	}

	// append query
	query := redirectURI.Query()
	for key, values := range rr.Query {
		for i := range values {
			query.Add(key, values[i])
		}
	}
	redirectURI.RawQuery = query.Encode()

	// parse fragment section
	redirectURI.Fragment = rr.Fragment.Encode()

	w.Header().Set("Location", redirectURI.String())
	w.WriteHeader(http.StatusTemporaryRedirect)
	return
}
