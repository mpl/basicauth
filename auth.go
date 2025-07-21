// 2015 - Mathieu Lonjaret

// Package basicauth provides HTTP basic access authentication.
package basicauth

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

type UserPass struct {
	U string // username
	P string // password
}

// NewUserPass takes a username:password string and returns a *UserPass.
func NewUserPass(userpass string) (*UserPass, error) {
	if userpass == "" {
		userpass = os.Getenv("AUTH_USERPASS")
		if userpass == "" {
			return &UserPass{}, nil
		}
	}

	if strings.HasPrefix(userpass, ":") {
		return &UserPass{
			P: strings.TrimPrefix(userpass, ":"),
		}, nil
	}
	if strings.HasSuffix(userpass, ":") {
		return &UserPass{
			U: strings.TrimSuffix(userpass, ":"),
		}, nil
	}
	pieces := strings.Split(userpass, ":")
	if len(pieces) != 2 {
		return nil, fmt.Errorf("wrong userpass format; got %q, wanted \"username:password\"", userpass)
	}
	return &UserPass{
		U: pieces[0],
		P: pieces[1],
	}, nil
}

// isAllowed returns whether req authenticates succesfully against up.
func (up *UserPass) isAllowed(req *http.Request) bool {
	if up == nil {
		return true
	}
	if up.U == "" && up.P == "" {
		return true
	}
	user, pass, ok := req.BasicAuth()
	if !ok {
		// TODO: log?
		return false
	}
	return user == up.U && pass == up.P
}

func sendUnauthorized(rw http.ResponseWriter, realm string) {
	rw.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realm))
	rw.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(rw, "<html><body><h1>Unauthorized</h1></body></html>")
}

type UserPassHandler struct {
	UP *UserPass
	H  http.Handler
	HF func(http.ResponseWriter, *http.Request)
}

func (uph *UserPassHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !uph.UP.isAllowed(r) {
		sendUnauthorized(w, "noneofyourbusiness")
		return
	}
	if uph.HF != nil {
		uph.HF(w, r)
		return
	}
	uph.H.ServeHTTP(w, r)
}
