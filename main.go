package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

type User struct {
	Username string
	Email    string
	Password string
}

var tpl *template.Template
var log = logrus.New()

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	log.Formatter = new(logrus.JSONFormatter)
	log.Level = logrus.InfoLevel
}

var dbUsers = map[string]User{}      // user ID, user
var dbSessions = map[string]string{} // session ID, user ID

func main() {
	u1 := User{"teste", "", "teste"}
	dbUsers["teste"] = u1

	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	// If user is not logged in, redirect to login
	user, err := alreadyLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// If user is logged in, render index page
	log.WithField("username", user.Username).Info("User accessed index")
	fmt.Fprintln(w, "Welcome back, ", user.Username)
}

func login(w http.ResponseWriter, r *http.Request) {
	// If user is already logged in, redirect to index
	if _, err := alreadyLoggedIn(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// If request is not POST, render login page
	if r.Method != http.MethodPost {
		err := tpl.ExecuteTemplate(w, "login.gohtml", nil)
		if err != nil {
			log.WithError(err).Error("Unable to load template")
			http.Error(w, "Unable to load template", http.StatusInternalServerError)
		}
		return
	}

	// If request is POST, parse form and authenticate user
	formUser, err := parseForm(r)
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Check if user exists and password is correct
	user, ok := dbUsers[formUser.Username]
	if !ok || user.Password != formUser.Password {
		log.Warn("Invalid login attempt")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create session cookie
	id := uuid.NewV4()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    id.String(),
		HttpOnly: true,
	})

	// Store session in db
	dbSessions[id.String()] = formUser.Username
	log.WithField("username", formUser.Username).Info("User logged in")
	// Redirect to index
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func signup(w http.ResponseWriter, r *http.Request) {
	// If user is already logged in, redirect to index
	if _, err := alreadyLoggedIn(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// If request is not POST, render signup page
	if r.Method != http.MethodPost {
		err := tpl.ExecuteTemplate(w, "signup.gohtml", nil)
		if err != nil {
			log.WithError(err).Error("Unable to load template")
			http.Error(w, "Unable to load template", http.StatusInternalServerError)
		}
	}

	// If request is POST, parse form and create new user
	formUser, err := parseForm(r)
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Check if username already exists
	if _, ok := dbUsers[formUser.Username]; ok {
		log.Warn("Username already exists")
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Create new user
	dbUsers[formUser.Username] = formUser

	log.WithFields(logrus.Fields{
		"username": formUser.Username,
		"email":    formUser.Email,
	}).Info("New user signed up")

	// Redirect to login
	http.Redirect(w, r, "/login", http.StatusSeeOther)

}

// alreadyLoggedIn checks if the user is already logged in by checking the session cookie.
// If the user is logged in, it returns the User struct. If the user is not logged in, it returns an error.
func alreadyLoggedIn(r *http.Request) (User, error) {
	// Check if session cookie exists
	c, err := r.Cookie("session")
	if err != nil {
		return User{}, fmt.Errorf("no session cookie")
	}

	// Check if session exists in db
	username, ok := dbSessions[c.Value]
	if !ok {
		return User{}, fmt.Errorf("invalid session cookie")
	}

	// Check if user exists in db
	if user, ok := dbUsers[username]; ok {
		return user, nil

	}

	// If user does not exist, return error
	return User{}, fmt.Errorf("user not found")
}

// parseForm parses the form data from the HTTP request and returns a User struct.
// It expects the form to contain "username", "email", and "password" fields.
// If the form cannot be parsed, it returns an error.
func parseForm(r *http.Request) (User, error) {
	err := r.ParseForm()
	if err != nil {
		return User{}, err
	}

	// Check if form values are not empty
	if r.FormValue("username") == "" || r.FormValue("email") == "" || r.FormValue("password") == "" {
		return User{}, fmt.Errorf("all fields are required")
	}

	formUser := User{
		Username: r.FormValue("username"),
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
	}

	return formUser, nil
}
