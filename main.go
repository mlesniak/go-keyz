package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func GenerateKey(bitSize int) (rsa.PublicKey, rsa.PrivateKey) {
	rng := rand.Reader
	key, _ := rsa.GenerateKey(rng, bitSize)
	pub := key.PublicKey
	return pub, *key
}

func main() {
	pub, key := GenerateKey(1024)

	rng := rand.Reader

	// Display public key.
	fmt.Println("--- Public")
	fmt.Println(pub.E)
	fmt.Println(pub.N)

	// Convert public key.
	fmt.Println("--- Public PEM key")
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&pub),
	}
	var buffer bytes.Buffer
	pem.Encode(&buffer, publicBlock)
	fmt.Println(buffer.String())

	// Display private key.
	fmt.Println("--- Private")
	fmt.Println(key.D)
	for _, prime := range key.Primes {
		fmt.Println(prime)
	}
	// Convert private key.
	fmt.Println("--- Private PEM key")
	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&key),
	}
	pem.Encode(os.Stdout, privateBlock)

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
	algorithm, err := aes.NewCipher(password)
	if err != nil {
		fmt.Println(err)
		return
	}
	gcm, err := cipher.NewGCM(algorithm)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rng, nonce)
	message = gcm.Seal(nonce, nonce, message, nil)
	fmt.Println(message)

	// Demo: decrypt directly
	fmt.Println("--- AES message (decrypted)")
	nonce, message = message[:gcm.NonceSize()], message[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, message, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(plain))

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
	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, &key, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plaintext)
}
