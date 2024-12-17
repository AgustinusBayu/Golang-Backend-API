package routes

import (
	"golang-api/api/handler"
	"os"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(router *gin.Engine) {
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "OK",
		})
	})

	router.POST("/register", handler.UserRegisterHandler)
	router.POST("/login", handler.LoginHandler)
	router.POST("/encrypt", handler.EncryptHandler)
	router.POST("/decrypt", handler.DecryptHandler)
	router.POST("/encryptFile", handler.EncryptFileHandler)
	router.POST("/decryptFile", handler.DecryptFileHandler)
}

func StartServer() {
	router := gin.Default()
	SetupRoutes(router)
	router.Run(os.Getenv("APP_PORT"))
}
