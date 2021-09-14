package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	GCMEncodeKey = "HarvestStars@GeekChomolungma"
	gcmBlockSize = 16
)

// EncodeAesGCM: encrypt a plain text with with predefined gcm key, return the ciphertext encoded as a base64 string
func EncodeAesGCM(plainString string) (string, error) {
	plainText := []byte(plainString)
	OutStr := base64.StdEncoding.EncodeToString(plainText)

	keyOrigin := []byte(GCMEncodeKey)
	key := make([]byte, 32)
	copy(key, keyOrigin)
	aes, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}

	task := make([]byte, gcmBlockSize)
	copy(task[4:], nonce)
	cipherText := aesgcm.Seal(task, nonce, []byte(OutStr), nil)

	// encode as base64 string
	encoded := base64.StdEncoding.EncodeToString(cipherText)
	return encoded, nil
}

//DecodeAesGCM : decode password with predefined gcm key
func DecodeAesGCM(encodedMsg string) (string, error) {
	keyOrigin := []byte(GCMEncodeKey)
	key := make([]byte, 32)
	copy(key, keyOrigin)
	encodedBytes, err := base64.StdEncoding.DecodeString(encodedMsg)
	if err != nil {
		fmt.Println("Error decoding encodedBytes:", err.Error())
		return "", err
	}

	aes, err := aes.NewCipher(key)
	aesgcm, err := cipher.NewGCM(aes)

	nonce, ciphertext := encodedBytes[4:4+aesgcm.NonceSize()], encodedBytes[4+aesgcm.NonceSize():]

	out, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("Error decoding out:", err.Error())
		return "", err
	}

	s, err := base64.StdEncoding.DecodeString(string(out))
	if err != nil {
		fmt.Println("Error decoding s:", err.Error())
		return "", err
	}
	return string(s), nil
}
