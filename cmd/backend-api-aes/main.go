package main

import (
	"golang-api/api/routes"
	"golang-api/utils/auth"
	"log"

	"github.com/joho/godotenv"
)

func main() {
	routes.StartServer()
}

func init() {

	if errInitPrivateKey := auth.InitPrivateKey("resource/private.key"); errInitPrivateKey != nil {
		log.Fatal(errInitPrivateKey)
	}

	if errInitPublicKey := auth.InitPublicKey("resource/public.key"); errInitPublicKey != nil {
		log.Fatal(errInitPublicKey)
	}

	err := godotenv.Load("config/.env")
	if err != nil {
		log.Fatal("Error loading .env file" + err.Error())
	}
}
