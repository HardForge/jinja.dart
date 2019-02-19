
package eciesgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"math/big"
)

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error) {
	var ct bytes.Buffer

	// Generate ephemeral key