package oasis_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-oasis/oasis"
)

func TestAuthorizeRequest(t *testing.T) {
	var ar *oasis.AuthorizeRequest
	var content []byte

	ar = &oasis.AuthorizeRequest{}
	content, _ = json.Marshal(ar)
	if want, have := `{"response_type":"","client_id":""}`, fmt.Sprintf("%s", content); want != have {
		t.Errorf("\nexpected: %s\ngot:      %s", want, have)
	}

	ar = &oasis.AuthorizeRequest{Stage: 1}
	content, _ = json.Marshal(ar)
	if want, have := `{"response_type":"","client_id":"","stage":1}`, fmt.Sprintf("%s", content); want != have {
		t.Errorf("\nexpected: %s\ngot:      %s", want, have)
	}
}
func TestAuthorizeDecoder_DecodeAuthorize(t *testing.T) {
	tests := []struct {
		decoderDesc   string
		decoder       oasis.AuthorizeDecoder
		queryDesc     string
		query         url.Values
		expected      *oasis.AuthorizeRequest
		expectedError string
	}{
		{
			decoderDesc: `allow only "code" response_type`,
			decoder:     oasis.NewAuthorizeDecoder("code"),
			queryDesc:   `provide "code" response_type`,
			query: url.Values{
				"response_type": {"code"},
				"client_id":     {"dummy-client"},
			},
			expected: &oasis.AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "dummy-client",
			},
		},
		{
			decoderDesc: `allow only "code" response_type`,
			decoder:     oasis.NewAuthorizeDecoder("code"),
			queryDesc:   `provide "token" response_type`,
			query: url.Values{
				"response_type": {"token"},
				"client_id":     {"dummy-client"},
			},
			expectedError: `response_type "token" is not allowed`,
		},
		{
			decoderDesc: `allow only "token" response_type`,
			decoder:     oasis.NewAuthorizeDecoder("token"),
			queryDesc:   `provide "token" response_type`,
			query: url.Values{
				"response_type": {"token"},
				"client_id":     {"dummy-client"},
			},
			expected: &oasis.AuthorizeRequest{
				ResponseType: "token",
				ClientID:     "dummy-client",
			},
		},
		{
			decoderDesc: `allow only "token" response_type`,
			decoder:     oasis.NewAuthorizeDecoder("token"),
			queryDesc:   `provide "code" response_type`,
			query: url.Values{
				"response_type": {"code"},
				"client_id":     {"dummy-client"},
			},
			expectedError: `response_type "code" is not allowed`,
		},
		{
			decoderDesc: `allow both "code" and "token" response_type`,
			decoder:     oasis.NewAuthorizeDecoder("token", "code"),
			queryDesc:   `provide "token" response_type`,
			query: url.Values{
				"response_type": {"token"},
				"client_id":     {"dummy-client"},
			},
			expected: &oasis.AuthorizeRequest{
				ResponseType: "token",
				ClientID:     "dummy-client",
			},
		},
		{
			decoderDesc: `allow no response_type`,
			decoder:     oasis.NewAuthorizeDecoder(),
			queryDesc:   `provide "token" response_type`,
			query: url.Values{
				"response_type": {"token"},
				"client_id":     {"dummy-client"},
			},
			expectedError: `response_type "token" is not allowed`,
		},
	}

	for _, test := range tests {
		// mock request
		r, _ := http.NewRequest(
			"GET",
			"/foobar/authorize?"+test.query.Encode(),
			nil,
		)

		_, ar, err := test.decoder.DecodeAuthorize(r)
		if test.expected != nil {
			ar.HTTPRequest = nil // no need to test the raw request
			if ar == nil {
				t.Logf("\ntesting: decoder %s\nagainst: query %s",
					test.decoderDesc, test.queryDesc)
				t.Errorf("expected *oasis.AuthorizeRequest, got nil")
			} else if want, have := *test.expected, *ar; want != have {
				t.Logf("\ntesting: decoder %s\nagainst: query %s",
					test.decoderDesc, test.queryDesc)
				t.Errorf("\nexpected: %#v\ngot:      %#v", want, have)
			}
		}
		if test.expectedError != "" {
			if err == nil {
				t.Logf("\ntesting: decoder %s\nagainst: query %s",
					test.decoderDesc, test.queryDesc)
				t.Errorf("expected error, got nil")
			} else if want, have := test.expectedError, err.Error(); want != have {
				t.Logf("\ntesting: decoder %s\nagainst: query %s",
					test.decoderDesc, test.queryDesc)
				t.Errorf("\nexpected: %#v\ngot:      %#v", want, have)
			}
		}
	}
}

func TestAuthorizeHandlerMux(t *testing.T) {
	var auth oasis.AuthorizeHandler
	var flag1, flag2 bool

	mux := oasis.NewAuthorizeHandlerMux()
	mux.AddFunc(oasis.StageInitialize, func(
		ctx context.Context,
		ar *oasis.AuthorizeRequest,
		decodeErr error,
	) (rd oasis.Responder) {
		if want, have := "hello-client-1", ar.ClientID; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
		flag1 = true
		return
	})
	mux.AddFunc(oasis.StageToAuthorize, func(
		ctx context.Context,
		ar *oasis.AuthorizeRequest,
		decodeErr error,
	) (rd oasis.Responder) {
		if want, have := "hello-client-2", ar.ClientID; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
		flag2 = true
		return
	})

	// ensure mux implements oasis.AuthorizeHandler
	auth = mux

	// test handler 1
	auth.HandleAuthorizeRequest(nil, &oasis.AuthorizeRequest{
		ClientID: "hello-client-1",
	}, nil)
	if want, have := true, flag1; want != have {
		t.Errorf("expected handler 1 to be run. not run")
	}

	// test handler 2
	auth.HandleAuthorizeRequest(nil, &oasis.AuthorizeRequest{
		Stage:    oasis.StageToAuthorize,
		ClientID: "hello-client-2",
	}, nil)
	if want, have := true, flag2; want != have {
		t.Errorf("expected handler 2 to be run. not run")
	}
}
