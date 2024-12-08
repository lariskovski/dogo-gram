package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/satori/go.uuid"
)

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

type User struct {
	Username string
	Email    string
	Password string
}

var dbUsers = map[string]User{}       // user ID, user
var dbSessions = map[string]string{}  // session ID, user ID

func signup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}
	
		data := User{
			Username: r.FormValue("username"),
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}
	
		dbUsers[data.Username] = data
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	err := tpl.ExecuteTemplate(w, "signup.gohtml", nil)
	if err != nil {
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		err := tpl.ExecuteTemplate(w, "login.gohtml", nil)
		if err != nil {
			http.Error(w, "Unable to load template", http.StatusInternalServerError)
		}
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	data := User{
		Username: r.FormValue("username"),
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
	}

	u, ok := dbUsers[data.Username]
	if !ok || u.Password != data.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	cookie, err := r.Cookie("session")
	if err == http.ErrNoCookie {
		id := uuid.NewV4()
		cookie = &http.Cookie{
			Name:     "session",
			Value:    id.String(),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		dbSessions[id.String()] = data.Username
		http.Redirect(w, r, "/bar", http.StatusSeeOther)
		return
	} else if err != nil {
		http.Error(w, "Unable to retrieve session cookie", http.StatusInternalServerError)
		return
	}
}

func bar(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username, ok := dbSessions[c.Value]
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user := dbUsers[username]
	fmt.Fprintln(w, "Welcome back,", user.Username)
}

func main() {
	http.HandleFunc("/", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/bar", bar)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
