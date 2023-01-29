
package eciesgo

import (
	"bytes"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
)

// PublicKey instance with nested elliptic.Curve interface (secp256k1 instance in our case)
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// NewPublicKeyFromHex decodes hex form of public key raw bytes and returns PublicKey instance
func NewPublicKeyFromHex(s string) (*PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cannot decode hex string: %w", err)
	}

	return NewPublicKeyFromBytes(b)
}

// NewPublicKeyFromBytes decodes public key raw bytes and returns PublicKey instance;
// Supports both compressed and uncompressed public keys
func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
	curve := getCurve()

	switch b[0] {
	case 0x02, 0x03:
		if len(b) != 33 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x := new(big.Int).SetBytes(b[1:])
		var ybit uint
		switch b[0] {
		case 0x02:
			ybit = 0
		case 0x03:
			ybit = 1
		}

		if x.Cmp(curve.Params().P) >= 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		// y^2 = x^3 + b
		// y   = sqrt(x^3 + b)
		var y, x3b big.Int
		x3b.Mul(x, x)
		x3b.Mul(&x3b, x)
		x3b.Add(&x3b, curve.Params().B)
		x3b.Mod(&x3b, curve.Params().P)
		if z := y.ModSqrt(&x3b, curve.Params().P); z == nil {
			return nil, fmt.Errorf("cannot parse public key")
		}