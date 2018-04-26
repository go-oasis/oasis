package oasis

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// AuthorizeStage represents the stage of process
// of this request.
//
// Value 0-99 are reserved to preset stages.
// You are recommended to use numbers above
// 100 for your custom stages.
type AuthorizeStage int

const (
	// StageInitialize is the default stage of
	// all AuthorizeRequest. It represents when
	// an AuthorizeRequest is just arrived.
	//
	// User is about to enter whatever login
	// information
	StageInitialize AuthorizeStage = iota

	// StageToAuthenticate represents when
	// an AuthorizeRequest is passed along
	// side with the login information
	// (i.e. submitted login form).
	//
	// If the authentication is success,
	// the AuthorizeRequest should jump
	// to StageToAuthorize.
	StageToAuthenticate

	// StageIntermediate represents an arbitrary
	// intermediate stage between StageToAuthenticate
	// and StageToAuthorize.
	//
	// That means user has login successfully but
	// has not yet authorize the given scope.
	StageIntermediate

	// StageToAuthorize represents when an
	// AuthorizeRequest is passed along side
	// with the authorization confirmation
	// (i.e. submitted confirmation of the
	// access scope).
	//
	// If the authorization is success,
	// the
	StageToAuthorize

	// StageCustom represents an arbitrary
	// custom stage.
	StageCustom
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
	HTTPRequest *http.Request `json:"-"`

	// ResponseType. REQUIRED.  Value MUST be set to "code" or "token".
	ResponseType string `json:"response_type"`

	// ClientID. REQUIRED. Is a unique string representing the registration
	// information provided by the client. Details specified in
	// RFC6749 section 2.2
	ClientID string `json:"client_id"`

	// RedirectURI. OPTIONAL. Absolute URI for authorization server
	// as described by RFC6749 section 3.1.2
	RedirectURI string `json:"redirect_uri,omitempty"`

	// Scope. OPTIONAL. The scope of access request as described by
	// RFC6749 section 3.3
	Scope string `json:"scope,omitempty"`

	// State. RECOMMENDED. An opaque value used by the client to
	// maintain state between the request and callback.
	//
	// The authorization server includes this value when redirecting
	// the user-agent back to the client. The parameter SHOULD be
	// used for preventing cross-site request forgery as described
	// in RFC6749 Section 10.12.
	State string `json:"state,omitempty"`

	// Stage. Library specific parameter to determine
	// the authorization stage.
	Stage AuthorizeStage `json:"stage,omitempty"`

	// UserID. Library specific parameter to store
	// the id of successfully authenticated user.
	UserID string `json:"user_id,omitempty"`
}

// AuthorizeDecoder decodes an http request as
// an AuthorizeRequest.
type AuthorizeDecoder interface {
	DecodeAuthorize(*http.Request) (context.Context, *AuthorizeRequest, error)
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
func (ad *DefaultAuthorizeDecoder) DecodeAuthorize(r *http.Request) (ctx context.Context, ar *AuthorizeRequest, err error) {

	// inherit the context from request
	ctx = r.Context()

	// construct authorize request as specified
	// in RFC.
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

// NewAuthorizeDecoder returns the default AuthorizeDecoder implementation
// which:
//
// 1. limits response_type to the allowedResponseTypes,
// 2. use the http.Request's context (i.e. `r.Context()` as context return).
func NewAuthorizeDecoder(allowedResponseTypes ...string) AuthorizeDecoder {
	allowedResponseTypesMap := make(map[string]bool)
	for _, responseType := range allowedResponseTypes {
		allowedResponseTypesMap[responseType] = true
	}
	return &DefaultAuthorizeDecoder{
		allowedResponseTypes: allowedResponseTypesMap,
	}
}

// AuthorizeHandler handles the Authorization Request.
//
// In RFC, the final response can either be an
// Authorization Response (for Authorization Grant),
// a Token Response (for Implicit Grant), or an
// Error Response. But in all these cases, the
// response is a URL redirection (i.e. RedirectResponse
// in this library)
//
// In practice, to process an authorization request,
// an authorization server would usually prompt
// intermediate user interface, includes and not
// limited to:
//
// 1. Login interface.
// 2. TOTP / MFA interface.
// 3. Scope review and authorization interface.
// 4. Prompt user for missing / invalid client identifier.
//
// In those cases, a ResponseCache would be used.
type AuthorizeHandler interface {
	HandleAuthorizeRequest(
		ctx context.Context,
		ar *AuthorizeRequest,
		decodeErr error,
	) (rd Responder)
}

// AuthorizeHandlerFunc is an adaptor to allow the use of ordinary
// functions as AuthorizeHandler.
type AuthorizeHandlerFunc func(
	ctx context.Context,
	ar *AuthorizeRequest,
	decodeErr error,
) (rd Responder)

// HandleAuthorizeRequest implements AuthorizeHandler
func (f AuthorizeHandlerFunc) HandleAuthorizeRequest(ctx context.Context, ar *AuthorizeRequest, decodeErr error) Responder {
	return f(ctx, ar, decodeErr)
}

// AuthorizeHandlerMux route different stage of AuthorizeRequest
// to different AuthorizeHandler.
type AuthorizeHandlerMux struct {
	handlers map[AuthorizeStage]AuthorizeHandler
}

// NewAuthorizeHandlerMux returns an initialized *AuthorizeHandlerMux
func NewAuthorizeHandlerMux() *AuthorizeHandlerMux {
	return &AuthorizeHandlerMux{
		handlers: make(map[AuthorizeStage]AuthorizeHandler),
	}
}

// Add a handler to handle specific stage.
//
// If 2 handlers are added to the same stage, the later one will
// overwrite the former one.
func (mux *AuthorizeHandlerMux) Add(stage AuthorizeStage, handler AuthorizeHandler) {
	mux.handlers[stage] = handler
}

// AddFunc add a function, as handler, to handle specific stage.
//
// If 2 handlers are added to the same stage, the later one will
// overwrite the former one.
func (mux *AuthorizeHandlerMux) AddFunc(stage AuthorizeStage, handler AuthorizeHandlerFunc) {
	mux.handlers[stage] = handler
}

// HandleAuthorizeRequest implements AuthorizeRequestHandler
func (mux *AuthorizeHandlerMux) HandleAuthorizeRequest(ctx context.Context, ar *AuthorizeRequest, decodeErr error) (rd Responder) {
	if handler, ok := mux.handlers[ar.Stage]; ok {
		return handler.HandleAuthorizeRequest(ctx, ar, decodeErr)
	}
	return &ResponseCache{
		Code:        http.StatusInternalServerError,
		HeaderCache: make(http.Header),
		Body:        strings.NewReader(http.StatusText(http.StatusInternalServerError)),
	}
}

// NewAuthorizeEndpoint returns an http.Handler
// to handle the authorization endpoint.
func NewAuthorizeEndpoint(
	actx Context,
	decoder AuthorizeDecoder,
	handler AuthorizeHandler,
	encoder ResponseEncoder,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithContext(r.Context(), &actx)
		ctx, ar, decodeErr := decoder.DecodeAuthorize(r.WithContext(ctx))
		rspr := handler.HandleAuthorizeRequest(ctx, ar, decodeErr)
		encoder.EncodeResponse(w, rspr)
	})
}
