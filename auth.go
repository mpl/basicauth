package basicauth

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
)

var (
	Verbose bool
	kBasicAuthPattern = regexp.MustCompile(`^Basic ([a-zA-Z0-9\+/=]+)`)
)

type UserPass struct {
	u string
	p string
}

func New(userpass string) (*UserPass, error) {
	if userpass == "" {
		return &UserPass{}, nil
	}
	if strings.HasPrefix(userpass, ":") {
		return &UserPass{
			p: strings.TrimPrefix(userpass, ":"),
		}, nil
	}
	if strings.HasSuffix(userpass, ":") {
		return &UserPass{
			u: strings.TrimSuffix(userpass, ":"),
		}, nil
	}
	pieces := strings.Split(userpass, ":")
	if len(pieces) != 2 {
		return nil, fmt.Errorf("wrong userpass format; got %q, wanted \"username:password\"", userpass)
	}
	return &UserPass{
		u: pieces[0],
		p: pieces[1],
	}, nil
}

func basicAuth(req *http.Request) (string, string, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", "", fmt.Errorf("Missing \"Authorization\" in header")
	}
	matches := kBasicAuthPattern.FindStringSubmatch(auth)
	if len(matches) != 2 {
		return "", "", fmt.Errorf("Bogus Authorization header")
	}
	encoded := matches[1]
	enc := base64.StdEncoding
	decBuf := make([]byte, enc.DecodedLen(len(encoded)))
	n, err := enc.Decode(decBuf, []byte(encoded))
	if err != nil {
		return "", "", err
	}
	pieces := strings.SplitN(string(decBuf[0:n]), ":", 2)
	if len(pieces) != 2 {
		return "", "", fmt.Errorf("bogus auth string; wanted \"username:password\"")
	}
	return pieces[0], pieces[1], nil
}

func (up *UserPass) IsAllowed(req *http.Request) bool {
	if up.u == "" && up.p == "" {
		return true
	}
	user, pass, err := basicAuth(req)
	if err != nil {
		if Verbose {
			log.Printf("Basic Auth: %v", err)
		}
		return false
	}
	return user == up.u && pass == up.p
}

func SendUnauthorized(rw http.ResponseWriter, req *http.Request, realm string) {
	rw.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realm))
	rw.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(rw, "<html><body><h1>Unauthorized</h1></body></html>")
}


