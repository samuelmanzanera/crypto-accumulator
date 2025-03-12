package main

import (
	"crypto/rand"
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

// SecretKey holds the secret parameter
type SecretKey struct {
	Alpha *big.Int
}

// NewSecretKey generates a new secret key on the G1 order
func NewSecretKey() (*SecretKey, error) {
	g1 := bls12381.NewG1()

	// Generate secret alpha by computing with the order of G1
	alpha, err := rand.Int(rand.Reader, g1.Q())
	if err != nil {
		return nil, err
	}

	return &SecretKey{Alpha: alpha}, nil
}

// ToPublicKey creates public key by scalar multiplication of the secret key over G2 generator
func (s SecretKey) ToPublicKey() PublicKey {
	// Generate the generator points for G1 and G2
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()

	// Compute pk.Alpha = g2^alpha
	pkAlpha := g2.New()
	g2.MulScalar(pkAlpha, g2.One(), bls12381.NewFr().FromBytes(s.Alpha.Bytes()))

	// Create the public key
	return PublicKey{
		G1:    g1.One(),
		G2:    g2.One(),
		Alpha: pkAlpha,
	}
}

// PublicKey holds the public counterpart of the secret
type PublicKey struct {
	G1    *bls12381.PointG1
	G2    *bls12381.PointG2
	Alpha *bls12381.PointG2 // g2^alpha
}
