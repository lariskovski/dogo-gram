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
var dbSessions = map[string]string{} // session ID, user ID

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
                cookie, err := r.Cookie("session")
                if err == http.ErrNoCookie {
                    id := uuid.NewV4()
                    cookie = &http.Cookie{
                        Name: "session",
                        Value: id.String(),
                        HttpOnly: true,
                    }
                    http.SetCookie(w, cookie)
                    dbSessions[id.String()] = data.Username
                    fmt.Println("Session created for user:", data.Username, "with session ID:", id.String())
					http.Redirect(w, r, "/bar", http.StatusSeeOther)
                } else if err != nil {
                    log.Fatal(err)
                } else {
                    fmt.Println("Session cookie already exists:", cookie.Value)
                }
                fmt.Fprintln(w, "Welcome back,", data.Username)
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

func bar(w http.ResponseWriter, r *http.Request) {
	// Get the cookie
	c, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		fmt.Fprintln(w, "No cookie found")
		return
	}

	// Get the user from the database
	u, ok := dbSessions[c.Value]
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		fmt.Fprintln(w, "No session for user")
		return
	}
	fmt.Fprintln(w, "Welcome back, ", u)
}

func main() {
	http.HandleFunc("/", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/bar", bar)
	http.ListenAndServe(":8080", nil)
}
