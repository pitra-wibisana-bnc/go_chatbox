// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"chatbox/handler"
	"chatbox/model"
	mysocket "chatbox/socket"
)

var mutex sync.RWMutex

func main() {
	// Init Logrus
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.DebugLevel)

	// Load .env Configuration
	err := godotenv.Load()
	if err != nil {
		logger.Error("Error Load .env : " + err.Error())
	} else {
		logger.Info(".env Loaded")
	}

	// Set Static Assets
	http.Handle("/assets/",
		http.StripPrefix("/assets/",
			http.FileServer(http.Dir("static/assets"))))

	// Set Static Routes
	// http.HandleFunc("/", handler.Home)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/view/index.html")
	})
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/view/register.html")
	})
	http.HandleFunc("/chat", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/view/chat.html")
	})

	// Init Engine Session
	var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

	// Auth Data
	authData := model.AuthData
	mutex.RLock()
	content, err := os.ReadFile("database.db")
	mutex.RUnlock()
	if err != nil {
		logger.Error("Error load database.db")
	} else {
		logger.Info("DB Loaded : " + string(content))

		var err = json.Unmarshal(content, &authData)
		if err != nil {
			logger.Error("Error unmarshal database.db")
		} else {
			logger.Info("DB Data Loaded : " + fmt.Sprintf("%d", len(authData)) + " row(s)")
		}
	}

	// Set Api Routes
	auth_handler := handler.NewAuthHandler(mutex, store, logger, authData)
	http.HandleFunc("/api/check_session", auth_handler.CheckSession)
	http.HandleFunc("/api/do_login", auth_handler.DoLogin)
	http.HandleFunc("/api/do_logout", auth_handler.DoLogout)
	http.HandleFunc("/api/do_register", auth_handler.DoRegister)
	
	// Running Hub
	flag.Parse()
	hub := mysocket.NewHub()
	go hub.Run()

	// Set Web Socket Routes
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		mysocket.ServeWs(hub, store, w, r)
	})

	// Listen Http Server
	var addr = flag.String("addr", ":"+os.Getenv("APP_PORT"), "http service address")
	err = http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	} else {
		fmt.Println()
	}
}
