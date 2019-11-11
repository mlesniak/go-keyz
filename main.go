package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
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

	// Encrypt message with password using AES.
	fmt.Println("--- AES message")
	message := []byte("Michael")
	aes, err := aes.NewCipher(password)
	if err != nil {
		fmt.Println(err)
		return
	}
	gcm, err := cipher.NewGCM(aes)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rng, nonce)
	message = gcm.Seal(message[:0], nonce, message, nil)
	fmt.Println(message)

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
