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
)

func GenerateKey(bitSize int) (rsa.PublicKey, rsa.PrivateKey) {
	rng := rand.Reader
	key, _ := rsa.GenerateKey(rng, bitSize)
	pub := key.PublicKey
	return pub, *key
}

func PublicKeyPEM(key rsa.PublicKey) string {
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&key),
	}
	var buffer bytes.Buffer
	pem.Encode(&buffer, publicBlock)
	return buffer.String()
}

func PrivateKeyPEM(key rsa.PrivateKey) string {
	publicBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(&key),
	}
	var buffer bytes.Buffer
	pem.Encode(&buffer, publicBlock)
	return buffer.String()
}

func main() {
	pub, key := GenerateKey(1024)

	publicPEM := PublicKeyPEM(pub)
	fmt.Println(publicPEM)
	privatePEM := PrivateKeyPEM(key)
	fmt.Println(privatePEM)

	// Generate random password.
	password := NewRandomPassword()
	fmt.Println("--- Password")
	fmt.Printf("%v\n", password)

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
	rng := rand.Reader
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

func NewRandomPassword() []byte {
	password := make([]byte, 32)
	_, err := rand.Reader.Read(password)
	if err != nil {
		panic(err)
	}
	return password
}
