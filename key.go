package main

import (
	"crypto/rand"
	"math/big"

	"github.com/cloudflare/bn256"
)

// SecretKey holds the secret parameter
type SecretKey struct {
	Alpha *big.Int
}

// NewSecretKey generates a new secret key on the bn256 order
func NewSecretKey() (*SecretKey, error) {
	// Generate secret alpha
	alpha, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, err
	}

	return &SecretKey{Alpha: alpha}, nil
}

// ToPublicKey creates public key by scalar multiplication of the secret key over G2 generator
func (s SecretKey) ToPublicKey() PublicKey {
	// Generate the generator points for G1 and G2
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1))  // G1 generator
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1)) // G2 generator

	// Compute pk.Alpha = g2^alpha
	pkAlpha := new(bn256.G2).ScalarMult(g2, s.Alpha)

	// Create the public key
	return PublicKey{
		G1:    g,
		G2:    g2,
		Alpha: pkAlpha,
	}
}

// PublicKey holds the public counterpart of the secret
type PublicKey struct {
	G1    *bn256.G1
	G2    *bn256.G2
	Alpha *bn256.G2 // g2^alpha
}
