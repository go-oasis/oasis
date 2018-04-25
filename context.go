package oasis

import "context"

// TokenFactory is the interface to produce different
// token strings with given context.
type TokenFactory interface{} // TODO: define me

// TokenStorage is the interface to retrieve all tokens includes,
// 1. Authorization Code (in Authorization Code Grant); and
// 2. Access Token (in Token Response); and
// 3. Refresh Token (in Token Response).
type TokenStorage interface{} // TODO: define me

// Context provides full handling of token
// creation and storage.
type Context struct {
	TokenStorage
	TokenFactory
}

type contextKey int

const (
	contextContext contextKey = iota
)

// WithContext embeds an *oasis.Context into a context.Context
func WithContext(parent context.Context, actx *Context) context.Context {
	return context.WithValue(parent, contextContext, actx)
}

// GetContext gets an *oasis.Context from a context.Context
func GetContext(ctx context.Context) *Context {
	raw := ctx.Value(contextContext)
	if raw == nil {
		return nil
	}
	return raw.(*Context)
}
