package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

func main() {
	rng := rand.Reader

	key, _ := rsa.GenerateKey(rng, 1024)
	pub := key.PublicKey

	// Display public key.
	fmt.Println("--- Public")
	fmt.Println(pub.E)
	fmt.Println(pub.N)

	// Display private key.
	fmt.Println("--- Private")
	fmt.Println(key.D)
	for _, prime := range key.Primes {
		fmt.Println(prime)
	}

	// Generate random password.
	password := make([]byte, 32)
	pwLen, err := rng.Read(password)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("--- Password")
	fmt.Printf("%d: %v\n", pwLen, password)

	// Encrypt password (for large messages) using public key.
	fmt.Println("--- Encrypting")
	secretMessage := password
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &pub, secretMessage, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(ciphertext)

	// Decrypt password using private key.
	fmt.Println("--- Decrypting")
	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, key, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plaintext)
}
