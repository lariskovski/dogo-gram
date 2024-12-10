package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Username string
	Email    string
	Password []byte
	Role	 string
	Images   []*Image
}

type Image struct {
	Filename string
	Owner    *User
	CreatedAt string
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
var dbImages = map[string]Image{}    // image ID, image

func main() {
	pwd, err := bcrypt.GenerateFromPassword([]byte("teste"), bcrypt.DefaultCost)
	if err != nil {
		log.WithError(err).Fatal("Unable to generate password hash")
	}
	dbUsers["teste"] = User{"teste", "", pwd, "user", nil}
	dbUsers["admin"] = User{"admin", "", pwd, "admin", nil}

	
	http.HandleFunc("/", index)
	http.HandleFunc("/admin", admin)
	http.HandleFunc("/upload", upload)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/logout", logout)
	
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.Handle("/images/", http.StripPrefix("/images", http.FileServer(http.Dir("./images"))))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	// If user is not logged in, redirect to login
	user, err := alreadyLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	fmt.Println(user.Images)
	// If user is logged in, render index page
	log.WithField("username", user.Username).Info("User accessed the index page")
	err = tpl.ExecuteTemplate(w, "index.gohtml", user)
	if err != nil {
		log.WithError(err).Error("Unable to load template")
		http.Error(w, "Unable to load template", http.StatusInternalServerError)
	}
}

func upload(w http.ResponseWriter, r *http.Request) {
	// If user is not logged in, redirect to login
	user, err := alreadyLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		// save uploaded file
		f, h, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "Unable to upload file", http.StatusBadRequest)
			return
		}
		defer f.Close()

		// read
		bs, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store on server
		dst, err := os.Create(filepath.Join("./images/", h.Filename))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		_, err = dst.Write(bs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// store in db
		dbImages[h.Filename] = Image{h.Filename, &user, h.Header.Get("Content-Type")}

		img := dbImages[h.Filename]
		user.Images = append(user.Images, &img)
		dbUsers[user.Username] = user // Update the user in the dbUsers map

		log.WithFields(logrus.Fields{ "filename": h.Filename, "username": user.Username }).Info("File uploaded")
		fmt.Println(user.Images)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func admin(w http.ResponseWriter, r *http.Request) {
	// If user is not logged in, redirect to login
	user, err := alreadyLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	// If user is not admin, redirect to index
	if user.Role != "admin" {
		fmt.Fprint(w, "You are not authorized to access this page")
		return
	}
	// If user is logged in and is admin, render admin page
	log.WithField("username", user.Username).Info("Admin accessed the admin page")
	fmt.Fprintf(w, "Welcome, %s %s!", user.Role, user.Username)
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
		fmt.Printf("Error: %v", err)
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Check if user exists and password is correct
	user, ok := dbUsers[formUser.Username]
	if !ok || bcrypt.CompareHashAndPassword(user.Password, []byte(r.FormValue("password"))) != nil {
		log.WithField("username", formUser.Username).Warn("Invalid login attempt")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create session cookie
	id := uuid.New()
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
		log.WithField("username", formUser.Username).Warn("Username already exists")
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

func logout(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	user, err := alreadyLoggedIn(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Delete session cookie
	c, _ := r.Cookie("session")
	delete(dbSessions, c.Value)
	c.MaxAge = -1
	http.SetCookie(w, c)

	log.WithField("username", user.Username).Info("User logged out")
	// Redirect to login
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// alreadyLoggedIn checks if the user is already logged in by checking the session cookie.
// If the user is logged in, it returns the User struct. If the session is invalid or the user is not found, it returns an error.
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
// It returns an error if any of the form fields are empty.
// It expects the form to contain "username", "email", and "password" fields.
// If the form cannot be parsed, it returns an error.
func parseForm(r *http.Request) (User, error) {
	err := r.ParseForm()
	if err != nil {
		return User{}, err
	}

	// Check if form values are not empty
	if r.FormValue("username") == "" || r.FormValue("password") == "" {
		return User{}, fmt.Errorf("all fields are required")
	}

	// Hash password
	pwd, err := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")), bcrypt.DefaultCost)
	if err != nil {
		return User{}, fmt.Errorf("unable to hash password")
	}
	formUser := User{
		Username: r.FormValue("username"),
		Email:    r.FormValue("email"),
		Password: pwd,
	}
	return formUser, nil
}
