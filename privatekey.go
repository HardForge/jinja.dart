
package eciesgo

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
)

// PrivateKey is an instance of secp256k1 private key with nested public key
type PrivateKey struct {
	*PublicKey
	D *big.Int
}

// GenerateKey generates secp256k1 key pair
func GenerateKey() (*PrivateKey, error) {
	curve := getCurve()

	p, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %w", err)
	}

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(p),
	}, nil
}

// NewPrivateKeyFromHex decodes hex form of private key raw bytes, computes public key and returns PrivateKey instance
func NewPrivateKeyFromHex(s string) (*PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cannot decode hex string: %w", err)
	}

	return NewPrivateKeyFromBytes(b), nil
}

// NewPrivateKeyFromBytes decodes private key raw bytes, computes public key and returns PrivateKey instance
func NewPrivateKeyFromBytes(priv []byte) *PrivateKey {
	curve := getCurve()
	x, y := curve.ScalarBaseMult(priv)

	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(priv),
	}
}