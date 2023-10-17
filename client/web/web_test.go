// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestQnapAuthnURL(t *testing.T) {
	query := url.Values{
		"qtoken": []string{"token"},
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "localhost http",
			in:   "http://localhost:8088/",
			want: "http://localhost:8088/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "localhost https",
			in:   "https://localhost:5000/",
			want: "https://localhost:5000/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "IP http",
			in:   "http://10.1.20.4:80/",
			want: "http://10.1.20.4:80/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "IP6 https",
			in:   "https://[ff7d:0:1:2::1]/",
			want: "https://[ff7d:0:1:2::1]/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "hostname https",
			in:   "https://qnap.example.com/",
			want: "https://qnap.example.com/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "invalid URL",
			in:   "This is not a URL, it is a really really really really really really really really really really really really long string to exercise the URL truncation code in the error path.",
			want: "http://localhost/cgi-bin/authLogin.cgi?qtoken=token",
		},
		{
			name: "err != nil",
			in:   "http://192.168.0.%31/",
			want: "http://localhost/cgi-bin/authLogin.cgi?qtoken=token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := qnapAuthnURL(tt.in, query)
			if u != tt.want {
				t.Errorf("expected url: %q, got: %q", tt.want, u)
			}
		})
	}
}

// TestServeAPI tests the web client api's handling of
//  1. invalid endpoint errors
//  2. localapi proxy allowlist
func TestServeAPI(t *testing.T) {
	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	// Serve dummy localapi. Just returns "success".
	localapi := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "success")
	})}
	defer localapi.Close()

	go localapi.Serve(lal)
	s := &Server{lc: &tailscale.LocalClient{Dial: lal.Dial}}

	tests := []struct {
		name       string
		reqPath    string
		wantResp   string
		wantStatus int
	}{{
		name:       "invalid_endpoint",
		reqPath:    "/not-an-endpoint",
		wantResp:   "invalid endpoint",
		wantStatus: http.StatusNotFound,
	}, {
		name:       "not_in_localapi_allowlist",
		reqPath:    "/local/v0/not-allowlisted",
		wantResp:   "/v0/not-allowlisted not allowed from localapi proxy",
		wantStatus: http.StatusForbidden,
	}, {
		name:       "in_localapi_allowlist",
		reqPath:    "/local/v0/logout",
		wantResp:   "success", // Successfully allowed to hit localapi.
		wantStatus: http.StatusOK,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api"+tt.reqPath, nil)
			w := httptest.NewRecorder()

			s.serveAPI(w, r)
			res := w.Result()
			defer res.Body.Close()
			if gotStatus := res.StatusCode; tt.wantStatus != gotStatus {
				t.Errorf("wrong status; want=%q, got=%q", tt.wantStatus, gotStatus)
			}
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			gotResp := strings.TrimSuffix(string(body), "\n") // trim trailing newline
			if tt.wantResp != gotResp {
				t.Errorf("wrong response; want=%q, got=%q", tt.wantResp, gotResp)
			}
		})
	}
}

func TestGetTailscaleBrowserSession(t *testing.T) {
	userA := &tailcfg.UserProfile{ID: tailcfg.UserID(1)}
	userB := &tailcfg.UserProfile{ID: tailcfg.UserID(2)}

	userANodeIP := "100.100.100.101"
	userBNodeIP := "100.100.100.102"
	taggedNodeIP := "100.100.100.103"

	var selfNode *ipnstate.PeerStatus
	tags := views.SliceOf([]string{"tag:server"})
	tailnetNodes := map[string]*apitype.WhoIsResponse{
		userANodeIP: {
			Node:        &tailcfg.Node{StableID: "Node1"},
			UserProfile: userA,
		},
		userBNodeIP: {
			Node:        &tailcfg.Node{StableID: "Node2"},
			UserProfile: userB,
		},
		taggedNodeIP: {
			Node: &tailcfg.Node{StableID: "Node3", Tags: tags.AsSlice()},
		},
	}

	lal := memnet.Listen("local-tailscaled.sock:80")
	defer lal.Close()
	// Serve a testing localapi handler so we can simulate
	// whois responses without a functioning tailnet.
	localapi := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/localapi/v0/whois":
			addr := r.URL.Query().Get("addr")
			if addr == "" {
				t.Fatalf("/whois call missing \"addr\" query")
			}
			if node := tailnetNodes[addr]; node != nil {
				if err := json.NewEncoder(w).Encode(&node); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				return
			}
			http.Error(w, "not a node", http.StatusUnauthorized)
			return
		case "/localapi/v0/status":
			status := ipnstate.Status{Self: selfNode}
			if err := json.NewEncoder(w).Encode(status); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			return
		default:
			// Only the above two endpoints get triggered from getTailscaleBrowserSession.
			// No need to mock any of the other localapi endpoint.
			t.Fatalf("unhandled localapi test endpoint %q, add to localapi handler func in test", r.URL.Path)
		}
	})}
	defer localapi.Close()
	go localapi.Serve(lal)

	s := &Server{lc: &tailscale.LocalClient{Dial: lal.Dial}}

	// Add some browser sessions to cache state.
	userASession := &browserSession{
		ID:            "cookie1",
		SrcNode:       "Node1",
		SrcUser:       userA.ID,
		Authenticated: time.Time{}, // not yet authenticated
	}
	userBSession := &browserSession{
		ID:            "cookie2",
		SrcNode:       "Node2",
		SrcUser:       userB.ID,
		Authenticated: time.Now().Add(-2 * sessionCookieExpiry), // expired
	}
	userASessionAuthorized := &browserSession{
		ID:            "cookie3",
		SrcNode:       "Node1",
		SrcUser:       userA.ID,
		Authenticated: time.Now(), // authenticated and not expired
	}
	s.browserSessions.Store(userASession.ID, userASession)
	s.browserSessions.Store(userBSession.ID, userBSession)
	s.browserSessions.Store(userASessionAuthorized.ID, userASessionAuthorized)

	tests := []struct {
		name       string
		selfNode   *ipnstate.PeerStatus
		remoteAddr string
		cookie     string

		wantSession      *browserSession
		wantError        error
		wantIsAuthorized bool // response from session.isAuthorized
	}{
		{
			name:        "not-connected-over-tailscale",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  "77.77.77.77",
			wantSession: nil,
			wantError:   errNotUsingTailscale,
		},
		{
			name:        "no-session-user-self-node",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  userANodeIP,
			cookie:      "not-a-cookie",
			wantSession: nil,
			wantError:   errNoSession,
		},
		{
			name:        "no-session-tagged-self-node",
			selfNode:    &ipnstate.PeerStatus{ID: "self", Tags: &tags},
			remoteAddr:  userANodeIP,
			wantSession: nil,
			wantError:   errNoSession,
		},
		{
			name:        "not-owner",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  userBNodeIP,
			wantSession: nil,
			wantError:   errNotOwner,
		},
		{
			name:        "tagged-source",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  taggedNodeIP,
			wantSession: nil,
			wantError:   errTaggedSource,
		},
		{
			name:        "has-session",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:  userANodeIP,
			cookie:      userASession.ID,
			wantSession: userASession,
			wantError:   nil,
		},
		{
			name:             "has-authorized-session",
			selfNode:         &ipnstate.PeerStatus{ID: "self", UserID: userA.ID},
			remoteAddr:       userANodeIP,
			cookie:           userASessionAuthorized.ID,
			wantSession:      userASessionAuthorized,
			wantError:        nil,
			wantIsAuthorized: true,
		},
		{
			name:        "session-associated-with-different-source",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userB.ID},
			remoteAddr:  userBNodeIP,
			cookie:      userASession.ID,
			wantSession: nil,
			wantError:   errNoSession,
		},
		{
			name:        "session-expired",
			selfNode:    &ipnstate.PeerStatus{ID: "self", UserID: userB.ID},
			remoteAddr:  userBNodeIP,
			cookie:      userBSession.ID,
			wantSession: nil,
			wantError:   errNoSession,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selfNode = tt.selfNode
			r := &http.Request{RemoteAddr: tt.remoteAddr, Header: http.Header{}}
			if tt.cookie != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.cookie})
			}
			session, err := s.getTailscaleBrowserSession(r)
			if !errors.Is(err, tt.wantError) {
				t.Errorf("wrong error; want=%v, got=%v", tt.wantError, err)
			}
			if diff := cmp.Diff(session, tt.wantSession); diff != "" {
				t.Errorf("wrong session; (-got+want):%v", diff)
			}
			if gotIsAuthorized := session.isAuthorized(); gotIsAuthorized != tt.wantIsAuthorized {
				t.Errorf("wrong isAuthorized; want=%v, got=%v", tt.wantIsAuthorized, gotIsAuthorized)
			}
		})
	}
}
