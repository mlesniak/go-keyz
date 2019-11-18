package main

import (
	"flag"
	"io/ioutil"
	"os"
)

// Name of the default public key for key generation.
const publicKeyName = "public.key"

// Name of the default private key for key generation and decryption.
const privateKeyName = "private.key"

// cli defines the data structure which is filled by parseFlags to determine the actual action.
type cli struct {
	keygen        bool
	encrypt       bool
	decrypt       bool
	publicKeyName string
}

// main handles CLI parsing and calls the correct function.
func main() {
	cli := parseFlags()

	switch {
	case cli.keygen:
		generateKeys()
	case cli.encrypt:
		startEncryption(cli.publicKeyName)
	case cli.decrypt:
		startDecryption()
	default:
		flag.Usage()
	}
}

// generateKeys generates a new key pair and stores them in standard file locations.
func generateKeys() {
	pub, priv := GenerateKey(1024)
	pubFile, err := os.Create(publicKeyName)
	if err != nil {
		panic(err)
	}
	pubFile.WriteString(publicKeyPEM(&pub))
	pubFile.Close()
	privFile, err := os.Create(privateKeyName)
	if err != nil {
		panic(err)
	}
	privFile.WriteString(privateKeyPEM(&priv))
	privFile.Close()
}

// startEncryption starts encryption of stdin using the provided public key name.
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

// startDecryption decrypts stdin (and output to stdout) using the previously generated private key.
func startDecryption() {
	pemPrivateKey, err := ioutil.ReadFile(privateKeyName)
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

// parseFlags defines all relevant flags and their default values.
func parseFlags() cli {
	var cli cli
	flag.BoolVar(&cli.keygen, "k", false, "Create a new key pair")
	flag.BoolVar(&cli.encrypt, "e", false, "Encrypt from stdin")
	flag.BoolVar(&cli.decrypt, "d", false, "Decrypt from stdin")
	flag.StringVar(&cli.publicKeyName, "p", "", "Public key file name for encryption")
	flag.Parse()
	return cli
}
