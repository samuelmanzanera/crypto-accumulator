package main

import (
	"crypto/sha256"
	"math/big"

	"github.com/cloudflare/bn256"
)

// Element represents an element in the group
type Element struct {
	Value *bn256.G1
	X     *big.Int
}

func HashToInt(message []byte) *big.Int {
	h := sha256.New()
	h.Write(message)
	hash := h.Sum(nil)
	// Ensure the value is within the BN256 order
	return new(big.Int).Mod(new(big.Int).SetBytes(hash), bn256.Order)
}
