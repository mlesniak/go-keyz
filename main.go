package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io"
)

// TODO Data structures
// TODO Comments
// TODO CLI

func NewRandomPassword() []byte {
	password := make([]byte, 32)
	_, err := rand.Reader.Read(password)
	if err != nil {
		panic(err)
	}
	return password
}

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

func EncryptSymmetric(message []byte) (password []byte, nonceSize int, data []byte) {
	password = NewRandomPassword()

	gcm := createGCMEncryptionWithAES(password)

	// Create random nonce and prepend it to the message.
	nonceSize = gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	io.ReadFull(rand.Reader, nonce)

	// EncryptSymmetric
	data = gcm.Seal(nonce, nonce, message, nil)
	return
}

func createGCMEncryptionWithAES(password []byte) cipher.AEAD {
	// Create AES instance using random password.
	algorithm, err := aes.NewCipher(password)
	if err != nil {
		panic(err)
	}
	// Create corresponding block encryption.
	gcm, err := cipher.NewGCM(algorithm)
	if err != nil {
		panic(err)
	}
	return gcm
}

func EncryptAsymmetric(message []byte, key *rsa.PublicKey) []byte {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, message, nil)
	if err != nil {
		panic(err)
	}
	return ciphertext
}

func DecryptSymmetric(data []byte, nonceSize int, password []byte) []byte {
	nonce, message := data[:nonceSize], data[nonceSize:]
	gcm := createGCMEncryptionWithAES(password)
	plain, err := gcm.Open(nil, nonce, message, nil)
	if err != nil {
		panic(err)
	}
	return plain
}

func DecryptAsymmetric(message []byte, key *rsa.PrivateKey) []byte {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, key, message, nil)
	if err != nil {
		panic(err)
	}
	return plaintext
}

// Message in -> encrypted data out
type EncryptedData struct {
	Data              []byte // Protected by AES.
	EncryptedPassword []byte // Protected by private key.
	NonceSize         int
}

func Encrypt(data []byte, key *rsa.PublicKey) []byte {
	password, nonceSize, data := EncryptSymmetric(data)
	encryptedPassword := EncryptAsymmetric(password, key)

	ed := EncryptedData{data, encryptedPassword, nonceSize}
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(ed)
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func Decrypt(data []byte, key *rsa.PrivateKey) []byte {
	dec := gob.NewDecoder(bytes.NewReader(data))
	var ed EncryptedData
	err := dec.Decode(&ed)
	if err != nil {
		panic(err)
	}

	password := DecryptAsymmetric(ed.EncryptedPassword, key)
	decryptedPlaintext := DecryptSymmetric(ed.Data, ed.NonceSize, password)
	return decryptedPlaintext
}

func main() {
	pub, priv := GenerateKey(1024)

	b := Encrypt([]byte("Hello, world!"), &pub)
	fmt.Println(b)

	message := Decrypt(b, &priv)
	fmt.Println(string(message))
}
