# basicauth
HTTP basic access authentication

Example:

	var up *basicauth.UserPass
	
	func makeHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if e, ok := recover().(error); ok {
					http.Error(w, e.Error(), http.StatusInternalServerError)
					return
				}
			}()
			if up.IsAllowed(r) {
				fn(w, r)
			} else {
				basicauth.SendUnauthorized(w, r, "montorrent")
			}
		}
	}
	
	func main() {
		var err error
		up, err = basicauth.New("foo:bar")
		if err != nil {
			log.Fatal(err)
		}
	
		http.Handle("/", makeHandler(someHandler))
		http.ListenAndServe(*host, nil)
	}
