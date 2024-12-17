package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"golang-api/models"
	"golang-api/utils/aes"
	"golang-api/utils/auth"
	"golang-api/utils/mongo"
	"golang-api/utils/responses"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
)

func UserRegisterHandler(c *gin.Context) {
	defer TimeTrack(time.Now())
	var req models.RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client := mongo.MongoClientConnection()
	defer client.Disconnect(context.Background())

	Users := client.Database(os.Getenv("DATABASE")).Collection(os.Getenv("COLLECTION"))

	encryptedUsername, errUser := aes.UserEncrypt([]byte(req.Username), req.Password)
	encryptedPassword, errPass := aes.Encrypt([]byte(req.Password), req.Password)

	if errPass != nil {
		c.JSON(http.StatusInternalServerError, responses.PassEncryptedFailedResponse())
		return
	}

	if errUser != nil {
		c.JSON(http.StatusInternalServerError, responses.UserEncryptedFailedResponse())
		return
	}

	user := models.Users{
		UserID:   uuid.New().String(),
		UserName: encryptedUsername,
		Password: encryptedPassword,
	}

	_, err := Users.InsertOne(context.Background(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, responses.UserRegistrationFailedResponse())
		return
	}

	c.JSON(http.StatusCreated, responses.UserRegisteredResponse())
}

func LoginHandler(c *gin.Context) {
	defer TimeTrack(time.Now())
	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client := mongo.MongoClientConnection()
	defer client.Disconnect(context.Background())

	Users := client.Database(os.Getenv("DATABASE")).Collection(os.Getenv("COLLECTION"))
	encryptedUsername, errUser := aes.UserEncrypt([]byte(req.Username), req.Password)

	if errUser != nil {
		c.JSON(http.StatusInternalServerError, responses.UserEncryptedFailedResponse())
		return
	}

	var user models.Users

	filter := bson.D{{Key: "user_name", Value: encryptedUsername}}
	err := Users.FindOne(context.Background(), filter).Decode(&user)

	if err != nil {
		c.JSON(http.StatusUnauthorized, responses.UserFailedLoginResponse())
		return
	}

	encryptedPassword, errPass := aes.Decrypt(user.Password, req.Password)

	if errPass != nil {
		c.JSON(http.StatusInternalServerError, responses.UserEncryptedFailedResponse())
		return
	}

	if string(encryptedPassword) == req.Password {
		token, errToken := auth.GenerateToken(req.Username)

		if err != errToken {
			c.JSON(http.StatusUnauthorized, responses.UserFailedLoginResponse())
			return
		}

		c.JSON(http.StatusOK, responses.LoginResponse(token))
		return
	}

	c.JSON(http.StatusUnauthorized, responses.UserFailedLoginResponse())
}

func EncryptHandler(c *gin.Context) {
	defer TimeTrack(time.Now())

	_, err := auth.TokenValid(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, responses.BadRequestResponse(err.Error()))
		return
	}

	var req models.RequestEncrypt
	var bodyBytes []byte
	var extraData map[string]interface{}

	if c.Request.Body != nil {
		bodyBytes, err = io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, responses.BadRequestResponse(err.Error()))
			return
		}
	}

	if err := json.Unmarshal(bodyBytes, &extraData); err != nil {
		c.JSON(http.StatusBadRequest, responses.BadRequestResponse(err.Error()))
		return
	}

	for key := range extraData {
		if strings.ToUpper(key) != "TEXT" && strings.ToUpper(key) != "PASSWORD" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Extra field '%s' is not allowed", key)})
			return
		}
	}

	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		c.JSON(http.StatusBadRequest, responses.BadRequestResponse(err.Error()))
		return
	}

	encrypted, err := aes.Encrypt([]byte(req.Text), req.Password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, responses.EncryptedFailedResponse())
		return
	}

	c.JSON(http.StatusOK, responses.EncryptedResponse(encrypted))
}

func DecryptHandler(c *gin.Context) {
	defer TimeTrack(time.Now())

	_, err := auth.TokenValid(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var req models.RequestDecrypt

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	decrypted, err := aes.Decrypt(req.Text, req.Password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, responses.DecryptedFailedResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, responses.DecryptedResponse(string(decrypted)))
}

// Tambahkan handler ini di dalam package handler

func EncryptFileHandler(c *gin.Context) {
	defer TimeTrack(time.Now())

	_, err := auth.TokenValid(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mengambil password dari query params atau body
	password := c.PostForm("password")
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
		return
	}

	// Mengambil file dari form data
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}

	// Membuka file
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file"})
		return
	}
	defer src.Close()

	// Membaca konten file
	fileData, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}

	// Mengenkripsi konten file
	encryptedData, err := aes.EncryptFile(fileData, password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, responses.EncryptedFailedResponse())
		return
	}

	// decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode encrypted data"})
	// 	return
	// }

	// Mengatur header respons untuk mengunduh file
	// Menggunakan nama file asli dan ekstensi yang sama
	originalFileName := file.Filename
	c.Header("Content-Disposition", "attachment; filename="+originalFileName) // Menjaga nama file asli
	c.Header("Content-Type", file.Header.Get("Content-Type"))                 // Menggunakan Content-Type dari file asli
	c.Header("Content-Length", fmt.Sprintf("%d", len(encryptedData)))         // Mengatur panjang konten

	// Mengirimkan data terenkripsi sebagai file
	c.Data(http.StatusOK, file.Header.Get("Content-Type"), encryptedData)
}

func DecryptFileHandler(c *gin.Context) {
	defer TimeTrack(time.Now())

	_, err := auth.TokenValid(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Mengambil password dari query params atau body
	password := c.PostForm("password")
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
		return
	}

	// Mengambil file dari form data
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}

	// Membuka file
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to open file"})
		return
	}
	defer src.Close()

	// Membaca konten file
	fileData, err := io.ReadAll(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}

	// Mendekripsi konten file
	decryptedData, err := aes.DecryptFile(fileData, password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, responses.DecryptedFailedResponse(err.Error()))
		return
	}

	// decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode encrypted data"})
	// 	return
	// }

	// Mengatur header respons untuk mengunduh file
	// Menggunakan nama file asli dan ekstensi yang sama
	originalFileName := file.Filename
	c.Header("Content-Disposition", "attachment; filename="+originalFileName) // Menjaga nama file asli
	c.Header("Content-Type", file.Header.Get("Content-Type"))                 // Menggunakan Content-Type dari file asli
	c.Header("Content-Length", fmt.Sprintf("%d", len(decryptedData)))         // Mengatur panjang konten

	// Mengirimkan data terenkripsi sebagai file
	c.Data(http.StatusOK, file.Header.Get("Content-Type"), decryptedData)
}

func TimeTrack(start time.Time) {
	elapsed := time.Since(start)

	// Skip this function, and fetch the PC and file for its parent.
	pc, _, _, _ := runtime.Caller(1)

	// Retrieve a function object this functions parent.
	funcObj := runtime.FuncForPC(pc)

	// Regex to extract just the function name (and not the module path).
	runtimeFunc := regexp.MustCompile(`^.*\.(.*)$`)
	name := runtimeFunc.ReplaceAllString(funcObj.Name(), "$1")

	log.Println(fmt.Sprintf("%s took %s", name, elapsed))
}
