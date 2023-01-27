package model

type Auth struct {
	Id       int
	Email    string
	Password string
	Name     string
}

var AuthData = []Auth{}
