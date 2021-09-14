package main

import (
	"fmt"

	"github.com/HarvestStars/AES-GCM/crypto"
)

func main() {
	testString := "test123"
	encodedStr, _ := crypto.EncodeAesGCM(testString)
	decodedStr, _ := crypto.DecodeAesGCM(encodedStr)
	fmt.Print(decodedStr)
}
