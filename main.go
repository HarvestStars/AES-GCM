package main

import (
	"fmt"

	"github.com/HarvestStars/AES-GCM/crypto"
)

func main() {
	testString := "Ph!abcdefg"

	encodedStr, _ := crypto.EncodeAesGCM(testString)
	fmt.Println("encodedStr is", encodedStr)

	decodedStr, _ := crypto.DecodeAesGCM(encodedStr)
	fmt.Println("decodedStr is", decodedStr)
}
