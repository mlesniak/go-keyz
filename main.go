package main

import (
	"flag"
	"io/ioutil"
	"os"
)

func main() {
	var keygen bool
	var encrypt bool
	var decrypt bool
	var publicKeyName string
	parseFlags(&keygen, &encrypt, &decrypt, &publicKeyName)

	switch {
	case keygen:
		generateKeys()
	case encrypt:
		startEncryption(publicKeyName)
	case decrypt:
		startDecryption()
	default:
		flag.Usage()
	}
}

func generateKeys() {
	pub, priv := GenerateKey(1024)
	pubFile, err := os.Create("public.key")
	if err != nil {
		panic(err)
	}
	pubFile.WriteString(publicKeyPEM(&pub))
	pubFile.Close()
	privFile, err := os.Create("private.key")
	if err != nil {
		panic(err)
	}
	privFile.WriteString(privateKeyPEM(&priv))
	privFile.Close()
}

func startEncryption(publicKeyName string) {
	if publicKeyName == "" {
		flag.Usage()
		return
	}
	pemPublicKey, err := ioutil.ReadFile(publicKeyName)
	if err != nil {
		panic(err)
	}
	publicKey := readPublicKey(pemPublicKey)
	bs, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	i := Encrypt(bs, publicKey)
	os.Stdout.Write(i)
}

func startDecryption() {
	pemPrivateKey, err := ioutil.ReadFile("private.key")
	if err != nil {
		panic(err)
	}
	privateKey := readPrivateKey(pemPrivateKey)
	bs, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	i := Decrypt(bs, privateKey)
	os.Stdout.Write(i)
}

func parseFlags(keygen *bool, encrypt *bool, decrypt *bool, publicKeyName *string) {
	flag.BoolVar(keygen, "k", false, "Create a new key pair")
	flag.BoolVar(encrypt, "e", false, "Encrypt from stdin")
	flag.BoolVar(decrypt, "d", false, "Decrypt from stdin")
	flag.StringVar(publicKeyName, "p", "", "Public key file name for encryption")
	flag.Parse()
}
