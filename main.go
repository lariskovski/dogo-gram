package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

var tpl *template.Template
var log = logrus.New()

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	log.Formatter = new(logrus.JSONFormatter)
	log.Level = logrus.InfoLevel
}

type User struct {
	Username string
	Email    string
	Password string
}

var dbUsers = map[string]User{}       // user ID, user
var dbSessions = map[string]string{}  // session ID, user ID


func main() {
	u1 := User{"teste", "", "teste"}
	dbUsers["teste"] = u1

	http.HandleFunc("/", bar)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	log.Fatal(http.ListenAndServe(":8080", nil))
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
	log.WithField("username", user.Username).Info("User accessed bar")
	fmt.Fprintln(w, "Welcome back,", user.Username)
}

func login(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	
	if r.Method != http.MethodPost {
		err := tpl.ExecuteTemplate(w, "login.gohtml", nil)
		if err != nil {
			log.WithError(err).Error("Unable to load template")
			http.Error(w, "Unable to load template", http.StatusInternalServerError)
		}
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.WithError(err).Error("Unable to parse form")
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
		log.Warn("Invalid login attempt")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	cookie, err := r.Cookie("session")
	if err == http.ErrNoCookie || dbSessions[cookie.Value] == "" {
		id := uuid.NewV4()
		cookie = &http.Cookie{
			Name:     "session",
			Value:    id.String(),
			HttpOnly: true,
		}
		http.SetCookie(w, cookie)
		dbSessions[id.String()] = data.Username
		log.WithField("username", data.Username).Info("User logged in")
		http.Redirect(w, r, "/bar", http.StatusSeeOther)
		return
	} else if err != nil {
		log.WithError(err).Error("Unable to retrieve session cookie")
		http.Error(w, "Unable to retrieve session cookie", http.StatusInternalServerError)
		return
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			log.WithError(err).Error("Unable to parse form")
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}
	
		data := User{
			Username: r.FormValue("username"),
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		if _, ok := dbUsers[data.Username]; ok {
			log.Warn("Username already exists")
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	
		dbUsers[data.Username] = data
		log.WithFields(logrus.Fields{
			"username": data.Username,
			"email":    data.Email,
		}).Info("New user signed up")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}

	err := tpl.ExecuteTemplate(w, "signup.gohtml", nil)
	if err != nil {
		log.WithError(err).Error("Unable to load template")
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
	}
}

func alreadyLoggedIn(r *http.Request) bool {
	c, err := r.Cookie("session")
	if err != nil {
		return false
	}

	username, ok := dbSessions[c.Value]
	if !ok {
		return false
	}

	_, ok = dbUsers[username]
	return ok
}

