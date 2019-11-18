// Utility functions to read and write rsa public and private keys from golang in an openssl-compatible format.
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// publicKeyPEM return the PEM block for a public key.
func publicKeyPEM(key *rsa.PublicKey) string {
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

// readPublicKey is the mirror function to publicKeyPEM and parses a public key.
func readPublicKey(data []byte) *rsa.PublicKey {
	block, _ := pem.Decode(data)
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

// privateKeyPEM returns the PEM block for a given private key.
func privateKeyPEM(key *rsa.PrivateKey) string {
	publicBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	var buffer bytes.Buffer
	pem.Encode(&buffer, publicBlock)
	return buffer.String()
}

// readPrivateKey is the mirror function to privateKeyPEM and parses a private key.
func readPrivateKey(data []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(data)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}
