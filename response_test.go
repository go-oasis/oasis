package oasis_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-oasis/oasis"
)

func TestResponseCache(t *testing.T) {
	var rspr oasis.Responder = &oasis.ResponseCache{
		Code: http.StatusInternalServerError,
		HeaderCache: http.Header{
			"X-Hello-World": {"silly hello"},
		},
		Body: strings.NewReader("hello world"),
	}
	w := httptest.NewRecorder()
	rspr.ResponseTo(w)

	if want, have := http.StatusInternalServerError, w.Code; want != have {
		t.Errorf("expected: %#v, got: %#v", want, have)
	}
	if want, have := "silly hello", w.Header().Get("X-Hello-World"); want != have {
		t.Errorf("expected: %#v, got: %#v", want, have)
	}
	if want, have := "hello world", w.Body.String(); want != have {
		t.Errorf("\nexpected: %s\ngot:      %s", want, have)
	}
}

func TestRedirectResponse(t *testing.T) {
	var rspr oasis.Responder

	tests := []struct {
		rspr          *oasis.RedirectResponse
		expected      string
		expectedError string
	}{
		{
			rspr: &oasis.RedirectResponse{
				HeaderCache: http.Header{
					"X-Hello-World": {"silly hello"},
				},
				RedirectURI: "https://foobar.com/path/oauth2?hello=world&foo=bar",
				Query: url.Values{
					"x-something": {"good"},
					"y-something": {"bad"},
					"z-something": {"ugly"},
				},
			},
			expected: "https://foobar.com/path/oauth2?foo=bar&hello=world&x-something=good&y-something=bad&z-something=ugly",
		},
		{
			rspr: &oasis.RedirectResponse{
				HeaderCache: http.Header{
					"X-Hello-World": {"silly hello"},
				},
				RedirectURI: "/path/oauth2?hello=world&foo=bar",
				Query: url.Values{
					"x-something": {"good"},
					"y-something": {"bad"},
					"z-something": {"ugly"},
				},
			},
			expectedError: `redirect_uri is misformed. expected a full URI but got "/path/oauth2?hello=world&foo=bar"`,
		},
	}

	for _, test := range tests {
		rspr = test.rspr
		w := httptest.NewRecorder()
		err := rspr.ResponseTo(w)

		if test.expected != "" {
			if want, have := http.StatusTemporaryRedirect, w.Code; want != have {
				t.Errorf("expected %#v, got %#v", want, have)
			}
			if want, have := w.Header().Get("Location"), test.expected; want != have {
				t.Errorf("\nexpected: %s\ngot:      %s", want, have)
			}
		}

		if test.expectedError != "" {
			if err == nil {
				t.Errorf("expected error, got nil")
			} else if want, have := test.expectedError, err.Error(); want != have {
				t.Errorf("\nexpected: %s\ngot:      %s", want, have)
			}
		}
	}

}
