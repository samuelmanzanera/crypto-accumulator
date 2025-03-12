package main

import (
	"crypto/sha256"
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

// Element represents an element in the group
type Element struct {
	Value *bls12381.PointG1
	X     *big.Int
}

func HashToInt(message []byte) *big.Int {
	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)
	// Ensure the value is within the BLS12-381 order
	r := bls12381.NewG1().Q()
	return new(big.Int).Mod(new(big.Int).SetBytes(hash), r)
}
