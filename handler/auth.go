package handler

import (
	"chatbox/model"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/sessions"
	"github.com/mervick/aes-everywhere/go/aes256"
	"github.com/sirupsen/logrus"
)

type AuthHandler struct {
	mutex    sync.RWMutex
	store    *sessions.CookieStore
	logger   *logrus.Logger
	authData []model.Auth
}

func NewAuthHandler(mutex sync.RWMutex, store *sessions.CookieStore, logger *logrus.Logger, authData []model.Auth) *AuthHandler {
	return &AuthHandler{
		mutex:    mutex,
		store:    store,
		logger:   logger,
		authData: authData,
	}
}

// Function for checking session
func (this *AuthHandler) CheckSession(w http.ResponseWriter, r *http.Request) {
	// Init Response
	response := make(map[string]interface{})

	// Get Session Data
	session, _ := this.store.Get(r, os.Getenv("SESSION_KEY"))

	// validate session is no data
	if len(session.Values) == 0 {
		response = map[string]interface{}{
			"status": "fail",
			"error":  "no sessions",
		}
	} else {
		response = map[string]interface{}{
			"status": "success",
			"data": map[string]string{
				"username": fmt.Sprintf("%v", session.Values["username"]),
				"name":     fmt.Sprintf("%v", session.Values["name"]),
			},
		}
	}

	// Write Response
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(response)
	if err != nil {
		this.logger.Error("Error happened in JSON marshal. Err: %s", err.Error())
	}
	w.Write(jsonResp)
}

// Function for checking user login
func (this *AuthHandler) DoLogin(w http.ResponseWriter, r *http.Request) {
	// Init Response
	response := make(map[string]string)

	username := strings.TrimSpace(r.PostFormValue("username"))
	password := strings.TrimSpace(r.PostFormValue("password"))

	if username == "" || password == "" {
		// Login Failed
		response["status"] = "fail"
		response["message"] = "Please fill form"
	} else {

		// Check User Data
		var user_data = &model.Auth{}
		user_data = nil
		if this.authData != nil && len(this.authData) > 0 {
			for _, user := range this.authData {
				if strings.ToLower(user.Email) == strings.ToLower(username) && aes256.Decrypt(user.Password, os.Getenv("ENCRYPT_KEY")) == password {
					user_data = &user
					break
				}
			}
		}

		if user_data == nil {
			// Login Failed
			response["status"] = "fail"
			response["message"] = "Invalid user or password"
		} else {

			// Login Success
			session, _ := this.store.Get(r, os.Getenv("SESSION_KEY"))

			session.Values["username"] = user_data.Email
			session.Values["password"] = user_data.Password
			session.Values["name"] = user_data.Name

			// Store session
			err := session.Save(r, w)
			if err != nil {
				this.logger.Fatal("Error test")
				response["status"] = "fail"
				response["message"] = "Something wrong in server"
			} else {
				this.logger.Info("Login [" + user_data.Email + "]")
				response["status"] = "success"
				response["message"] = "Login success"
			}

		}
	}

	// Write Response
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(response)
	if err != nil {
		this.logger.Error("Error happened in JSON marshal. Err: %s", err.Error())
	}
	w.Write(jsonResp)
}

// Function for logout session
func (this *AuthHandler) DoLogout(w http.ResponseWriter, r *http.Request) {
	// Init Response
	response := make(map[string]string)

	// Process get session
	session, _ := this.store.Get(r, os.Getenv("SESSION_KEY"))

	// Process to expired session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Logout Success
	response["status"] = "success"
	response["message"] = "Logout success"

	// Write Response
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(response)
	if err != nil {
		this.logger.Error("Error happened in JSON marshal. Err: %s", err.Error())
	}
	w.Write(jsonResp)
}

// Function for register new user
func (this *AuthHandler) DoRegister(w http.ResponseWriter, r *http.Request) {
	// Init Response
	response := make(map[string]string)

	username := strings.TrimSpace(r.PostFormValue("username"))
	password := strings.TrimSpace(r.PostFormValue("password"))
	name := strings.TrimSpace(r.PostFormValue("name"))

	if username == "" || password == "" || name == "" {
		// Register Failed
		response["status"] = "fail"
		response["message"] = "Please fill form"
	} else {

		// Check Duplicate Data
		var user_exists bool = false
		if this.authData != nil && len(this.authData) > 0 {
			for _, user := range this.authData {
				if strings.ToLower(user.Email) == strings.ToLower(username) {
					user_exists = true
					break
				}
			}
		}

		if user_exists {
			// Register Failed
			response["status"] = "fail"
			response["message"] = "User [" + username + "] already exists"
		} else {
			// Register Process
			new_data := model.Auth{
				Email:    username,
				Password: aes256.Encrypt(password, os.Getenv("ENCRYPT_KEY")),
				Name:     name,
			}
			this.authData = append(this.authData, new_data)

			json_byte, err := json.Marshal(this.authData)
			if err != nil {
				response["status"] = "fail"
				response["message"] = "Something wrong in server"
				this.logger.Error("Error Register Marshal", err.Error())
			} else {
				this.mutex.Lock()
				os.Remove("database.db")
				f, err := os.OpenFile("database.db", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
				if err != nil {
					response["status"] = "fail"
					response["message"] = "Something wrong in server"

					this.logger.Error("Error register write : " + err.Error())
				} else {
					f.WriteString(string(json_byte))

					response["status"] = "success"
					response["message"] = "Register Success"

					this.logger.Info("New User Registered [" + username + "] ")
				}
				f.Close()
				this.mutex.Unlock()

			}
		}

	}

	// Write Response
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	jsonResp, err := json.Marshal(response)
	if err != nil {
		this.logger.Error("Error happened in JSON marshal. Err: %s", err.Error())
	}
	w.Write(jsonResp)
}
