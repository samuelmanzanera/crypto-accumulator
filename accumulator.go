package main

import (
	"math/big"

	"github.com/cloudflare/bn256"
)

// Accumulator represents the current state
type Accumulator struct {
	Value *bn256.G1 // Accumulated value
}

// NewAccumulator creates a new accumulator on G1 generator
func NewAccumulator() Accumulator {
	g := new(bn256.G1).ScalarBaseMult(big.NewInt(1)) // G1 generator
	return Accumulator{Value: g}
}

// Add the element to the accumulator
func (a *Accumulator) Add(sk *SecretKey, elem *Element) {
	alphaPoint := new(bn256.G1).ScalarMult(a.Value, sk.Alpha)
	elemPoint := new(bn256.G1).Add(elem.Value, alphaPoint)
	a.Value = elemPoint
}
