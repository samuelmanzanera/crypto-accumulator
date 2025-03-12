package main

import (
	bls12381 "github.com/kilic/bls12-381"
)

// Accumulator represents the current state
type Accumulator struct {
	Value *bls12381.PointG1 // Accumulated value
}

// NewAccumulator creates a new accumulator on G1 generator
func NewAccumulator() Accumulator {
	g1 := bls12381.NewG1() // G1 generator
	return Accumulator{Value: g1.One()}
}

// Add the element to the accumulator
func (a *Accumulator) Add(sk *SecretKey, elem *Element) {
	g1 := bls12381.NewG1()
	alphaPoint := g1.New()
	g1.MulScalar(alphaPoint, a.Value, bls12381.NewFr().FromBytes(sk.Alpha.Bytes()))
	elemPoint := g1.New()
	g1.Add(elemPoint, elem.Value, alphaPoint)
	a.Value = elemPoint
}
