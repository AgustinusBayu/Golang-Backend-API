package responses

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	UserRegisteredMessage     = "User Succesfully registered"
	UserRegistrationFailed    = "Failed to register user"
	InvalidUserPassword       = "Invalid username or password"
	InvalidCredentialsMessage = "Invalid credentials"
	FailedUserEncrypted       = "Failed to encrypt username"
	FailedPassEncrypted       = "Failed to encrypt password"
)

func UserRegisteredResponse() gin.H {
	return gin.H{
		"status":      "success",
		"status_code": http.StatusCreated,
		"message":     UserRegisteredMessage,
	}
}

func UserRegistrationFailedResponse() gin.H {
	return gin.H{
		"status":      "error",
		"status_code": http.StatusInternalServerError,
		"message":     UserRegistrationFailed,
	}
}

func UserFailedLoginResponse() gin.H {
	return gin.H{
		"status":      "error",
		"status_code": http.StatusUnauthorized,
		"message":     InvalidUserPassword,
	}
}

func UserEncryptedFailedResponse() gin.H {
	return gin.H{
		"status":      "error",
		"status_code": http.StatusInternalServerError,
		"message":     FailedUserEncrypted,
	}
}

func PassEncryptedFailedResponse() gin.H {
	return gin.H{
		"status":      "error",
		"status_code": http.StatusInternalServerError,
		"message":     FailedPassEncrypted,
	}
}

func LoginResponse(token string) gin.H {
	return gin.H{
		"status":      "success",
		"status_code": http.StatusOK,
		"message":     "Login successful",
		"token":       token,
	}
}

func EncryptedFailedResponse() gin.H {
	return gin.H{
		"status":      "error",
		"status_code": http.StatusInternalServerError,
		"message":     "Failed to encrypt data",
	}
}

func EncryptedResponse(encrypted string) gin.H {
	return gin.H{
		"status":      "success",
		"status_code": http.StatusOK,
		"message":     "Data encrypted successfully",
		"encrypted":   encrypted,
	}
}

func DecryptedResponse(decrypted string) gin.H {
	return gin.H{
		"status":      "success",
		"status_code": http.StatusOK,
		"message":     "Data decrypted successfully",
		"decrypted":   decrypted,
	}
}

func DecryptedFailedResponse(message string) gin.H {

	return gin.H{
		"status":      "error",
		"status_code": http.StatusInternalServerError,
		"message":     message,
	}
}

func BadRequestResponse(message string) gin.H {
	return gin.H{
		"status":      "error",
		"status_code": http.StatusBadRequest,
		"message":     message,
	}
}
