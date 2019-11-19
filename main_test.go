// This package contains a "happy-flow" unit tests of the overall key-generation-encryption-decryption process.
// Further tests will be added for new features, regression tests on found bugs, ...
package main

import (
	"bytes"
	"math/rand"
	"testing"
)

func Test_main(t *testing.T) {
	message := []byte("Hello, golang world")

	// Fix random values
	rng := rand.New(rand.NewSource(11031981))
	fixRandomReader(rng)

	// Generate "random" key pair.
	//
	// Note that we do not yet compare the generated keys with a pre-defined public/private pair since the values
	// iterate between two possiblities; we have to further examine this behaviour.
	publicKey, privateKey := GenerateKey(1024)

	// Encrypt the message.
	encryptedMessage := Encrypt(message, &publicKey)

	// Decrypt and compare output.
	decryptedMessage := Decrypt(encryptedMessage, &privateKey)
	if bytes.Compare(message, decryptedMessage) != 0 {
		t.Error("Happy-Flow was not successful. Message not retrieved.")
	}
}
