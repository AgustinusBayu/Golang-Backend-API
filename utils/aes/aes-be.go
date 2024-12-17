package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang-api/models"
	"io"
	"log"
)

func GenerateHash(Text []byte) []byte {
	hash := sha256.Sum256(Text)
	return hash[:]
}

func UserEncrypt(userName []byte, password string) (string, error) {

	userName = append(userName, []byte(models.ValidKeyword)...)

	key := GenerateHash([]byte(password))
	block, err := aes.NewCipher(key)

	if err != nil {
		return "", err
	}

	iv := GenerateHash(userName)[:aes.BlockSize]
	cipherText := make([]byte, aes.BlockSize+len(userName))
	copy(cipherText[:aes.BlockSize], iv)

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], userName)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func Encrypt(plainText []byte, password string) (string, error) {

	plainText = append(plainText, []byte(models.ValidKeyword)...)

	key := GenerateHash([]byte(password))
	block, err := aes.NewCipher(key)

	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
	// return base64.StdEncoding.EncodeToString(append(iv, cipherText...)), nil
}

func Decrypt(encryptedText string, password string) ([]byte, error) {
	key := GenerateHash([]byte(password))
	log.Println(key)
	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	log.Println(cipherText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	if string(cipherText[len(cipherText)-len(models.ValidKeyword):]) != models.ValidKeyword {
		return nil, errors.New("invalid password or data")
	}

	return cipherText[:len(cipherText)-len(models.ValidKeyword)], nil
}

func EncryptFile(source []byte, password string) ([]byte, error) {

	source = append(source, []byte(models.ValidKeyword)...)

	key := GenerateHash([]byte(password))
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(source))
	iv := cipherText[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], source)

	return cipherText, nil
}

func DecryptFile(source []byte, password string) ([]byte, error) {
	key := GenerateHash([]byte(password))

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	if len(source) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := source[:aes.BlockSize]
	source = source[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(source, source)

	if string(source[len(source)-len(models.ValidKeyword):]) != models.ValidKeyword {
		return nil, errors.New("invalid password or data")
	}

	return source[:len(source)-len(models.ValidKeyword)], nil
}
