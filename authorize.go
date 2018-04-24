package oasis

import (
	"fmt"
	"net/http"
	"strings"
)

// AuthorizeRequest represents an Authorization Request for either the
// Authorization Code Grant (as described in RFC6749 section 4.1.1),
// or the Implicit Grant (as described in RFC6749 section 4.2.1).
//
// The request is constructed by client as the authorization endpoint
// with specified query components.
//
// If the AuthorizeRequest is generated from http.Request, it should
// be attached to attribute HTTPRequest.
type AuthorizeRequest struct {

	// HTTPRequest is the raw http.Request that this
	// AuthorizeRequest is constructed from, if any.
	HTTPRequest *http.Request

	// ResponseType. REQUIRED.  Value MUST be set to "code" or "token".
	ResponseType string `json:"response_type"`

	// ClientID. REQUIRED. Is a unique string representing the registration
	// information provided by the client. Details specified in
	// RFC6749 section 2.2
	ClientID string `json:"client_id"`

	// RedirectURI. OPTIONAL. Absolute URI for authorization server
	// as described by RFC6749 section 3.1.2
	RedirectURI string `json:"redirect_uri"`

	// Scope. OPTIONAL. The scope of access request as described by
	// RFC6749 section 3.3
	Scope string `json:"scope"`

	// State. RECOMMENDED. An opaque value used by the client to
	// maintain state between the request and callback.
	//
	// The authorization server includes this value when redirecting
	// the user-agent back to the client. The parameter SHOULD be
	// used for preventing cross-site request forgery as described
	// in RFC6749 Section 10.12.
	State string `json:"state"`
}

// AuthorizeDecoder decodes an http request as
// an AuthorizeRequest.
type AuthorizeDecoder interface {
	DecodeAuthorize(*http.Request) (*AuthorizeRequest, error)
}

// DefaultAuthorizeDecoder is the default AuthorizeDecoder implementation.
type DefaultAuthorizeDecoder struct {
	allowedResponseTypes map[string]bool
}

// DecodeAuthorize implements AuthorizeDecoder.
//
// It also validates the decoded AuthorizeRequest to the
// RFC6749 standard. An error will be returned response_type
// is not provided or is not in allowedResponseTypes array.
//
// An *AuthorizeRequest is always returned even if
// there is an error.
func (ad *DefaultAuthorizeDecoder) DecodeAuthorize(r *http.Request) (ar *AuthorizeRequest, err error) {
	ar = &AuthorizeRequest{
		ResponseType: strings.Trim(r.URL.Query().Get("response_type"), "\r\n\t "),
		ClientID:     strings.Trim(r.URL.Query().Get("client_id"), "\r\n\t "),
		RedirectURI:  strings.Trim(r.URL.Query().Get("redirect_uri"), "\r\n\t "),
		Scope:        strings.Trim(r.URL.Query().Get("scope"), "\r\n\t "),
		State:        strings.Trim(r.URL.Query().Get("state"), "\r\n\t "),
	}

	if ar.ResponseType == "" {
		err = fmt.Errorf("response_type is required but not set")
		return
	}
	if _, ok := ad.allowedResponseTypes[ar.ResponseType]; !ok {
		err = fmt.Errorf(`response_type "%s" is not allowed`, ar.ResponseType)
	}
	return
}

// NewAuthorizeDecoder returns AuthorizeDecoder limiting response_type
// to the allowedResponseTypes.
func NewAuthorizeDecoder(allowedResponseTypes ...string) AuthorizeDecoder {
	allowedResponseTypesMap := make(map[string]bool)
	for _, responseType := range allowedResponseTypes {
		allowedResponseTypesMap[responseType] = true
	}
	return &DefaultAuthorizeDecoder{
		allowedResponseTypes: allowedResponseTypesMap,
	}
}
