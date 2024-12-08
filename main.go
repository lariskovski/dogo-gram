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
	Username  string
	Email string
	Password string
}

var dbUsers = map[string]User{} // user ID, user

func signup(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		// Handle error
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "text/html")

	data := User{
		Username: r.FormValue("username"),
		Email: r.FormValue("email"),
		Password: r.FormValue("password"),
	}

	// Store the user in the database
	dbUsers[data.Username] = data

	err = tpl.ExecuteTemplate(w, "signup.gohtml", data)
	if err != nil {
		log.Fatal(err)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		// Handle error
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "text/html")

	if r.Method == http.MethodPost {
		data := User{
			Username: r.FormValue("username"),
			Email: r.FormValue("email"),
			Password: r.FormValue("password"),
		}
	
		if u, ok := dbUsers[data.Username]; ok {
			if u.Password == data.Password {
				fmt.Fprintln(w, "Welcome back, ", data.Username)
				_, err := r.Cookie("session")
				if err == http.ErrNoCookie {
					id := uuid.NewV4()
					// If no cookie is found, set a new cookie with value 0
					http.SetCookie(w, &http.Cookie{
						Name: "session",
						Value: id.String(),
						HttpOnly: true,
					})
				} else if err != nil {
					log.Fatal(err)
				}
			} else {
				fmt.Fprintln(w, "Invalid password")
	
			}
		} else {
			fmt.Fprintln(w, "User not found")
		}
	}
	err = tpl.ExecuteTemplate(w, "login.gohtml", nil)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// http.HandleFunc("/", session)
	http.HandleFunc("/", signup)
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}
