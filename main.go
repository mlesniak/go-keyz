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
	"flag"
	"io"
	"io/ioutil"
	"os"
)

// TODO Data structures
// TODO Comments
// TODO CLI
// TODO Constants for names

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

func PublicKeyPEM(key *rsa.PublicKey) string {
	bs, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		panic(err)
	}
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bs,
	}
	var buffer bytes.Buffer
	pem.Encode(&buffer, publicBlock)
	return buffer.String()
}

func PrivateKeyPEM(key *rsa.PrivateKey) string {
	publicBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	var buffer bytes.Buffer
	pem.Encode(&buffer, publicBlock)
	return buffer.String()
}

func ReadPrivateKey(data []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(data)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

func ReadPublicKey(data []byte) *rsa.PublicKey {
	block, _ := pem.Decode(data)
	//key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		panic(err)
	}

	return rsaKey
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
	//pub, priv := GenerateKey(1024)
	//
	//b := Encrypt([]byte("Hello, world!"), &pub)
	//fmt.Println(b)
	//
	//message := Decrypt(b, &priv)
	//fmt.Println(string(message))

	var keygen bool
	var encrypt bool
	var decrypt bool
	var publicKeyName string
	flag.BoolVar(&keygen, "k", false, "Create a new key pair")
	flag.BoolVar(&encrypt, "e", false, "Encrypt from stdin")
	flag.BoolVar(&decrypt, "d", false, "Decrypt from stdin")
	flag.StringVar(&publicKeyName, "p", "", "Public key file name for encryption")
	flag.Parse()

	if keygen {
		pub, priv := GenerateKey(1024)

		pubFile, err := os.Create("public.key")
		if err != nil {
			panic(err)
		}
		pubFile.WriteString(PublicKeyPEM(&pub))
		pubFile.Close()

		privFile, err := os.Create("private.key")
		if err != nil {
			panic(err)
		}
		privFile.WriteString(PrivateKeyPEM(&priv))
		privFile.Close()

		return
	}

	if decrypt {
		pemPrivateKey, err := ioutil.ReadFile("private.key")
		if err != nil {
			panic(err)
		}
		privateKey := ReadPrivateKey(pemPrivateKey)
		bs, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}

		i := Decrypt(bs, privateKey)
		os.Stdout.Write(i)
		return
	}

	if encrypt {
		if publicKeyName == "" {
			flag.Usage()
			return
		}

		pemPublicKey, err := ioutil.ReadFile(publicKeyName)
		if err != nil {
			panic(err)
		}
		publicKey := ReadPublicKey(pemPublicKey)

		bs, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}

		i := Encrypt(bs, publicKey)
		os.Stdout.Write(i)

		return
	}

	flag.Usage()
}
