package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
)

// Witness is the membership witness
type Witness struct {
	Value *bn256.G1
}

// Verify verifies the witness by checking the element is part of the accumulator
func (w Witness) Verify(acc *Accumulator, elem *Element, pk *PublicKey) bool {
	// e(w, g2^α) * e(g1^x, g2) = e(acc, g2)
	// where w is the witness, x is the element, acc is the accumulator value

	// Calculate e(w, g2^α)
	pair1 := bn256.Pair(w.Value, pk.Alpha)

	// Calculate e(g1^x, g2)
	pair2 := bn256.Pair(elem.Value, pk.G2)

	// Multiply the pairings
	lhs := new(bn256.GT).Add(pair1, pair2)

	// Calculate e(acc, g2)
	rhs := bn256.Pair(acc.Value, pk.G2)

	return lhs.String() == rhs.String()
}

// ZkProof creates a zero-knowledge proof of membership
func (w Witness) ZkProof(acc *Accumulator, elem *Element, pk *PublicKey) (*MembershipProof, error) {
	// Generate random value for blinding
	r, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %v", err)
	}

	// Create commitments
	t1 := new(bn256.G1).ScalarMult(w.Value, r)
	t2 := new(bn256.G2).ScalarMult(pk.G2, r)
	t3 := bn256.Pair(w.Value, pk.G2)

	commitment := &ProofCommitment{
		T1: t1,
		T2: t2,
		T3: t3,
	}

	// Generate challenge using hash of all public values
	challengeInput := []byte{}
	challengeInput = append(challengeInput, acc.Value.Marshal()...)
	challengeInput = append(challengeInput, elem.Value.Marshal()...)
	challengeInput = append(challengeInput, t1.Marshal()...)
	challengeInput = append(challengeInput, t2.Marshal()...)

	challenge := new(big.Int).SetBytes(challengeInput)
	challenge.Mod(challenge, bn256.Order)

	// Calculate response = r + challenge * x
	response := new(big.Int).Mul(challenge, elem.X)
	response.Add(response, r)
	response.Mod(response, bn256.Order)

	return &MembershipProof{
		Commitment: commitment,
		Response:   response,
	}, nil
}

// GenerateWitness generates a membership witness for the given element
func GenerateWitness(acc *Accumulator, sk *SecretKey, elem *Element) (*Witness, error) {
	// Witness computation: w = acc^(1/(x + α))
	// where x is the element value and α is the secret key

	// Calculate (x + α)
	sum := new(big.Int).Add(elem.X, sk.Alpha)

	// Calculate modular multiplicative inverse
	inv := new(big.Int).ModInverse(sum, bn256.Order)
	if inv == nil {
		return nil, fmt.Errorf("failed to compute inverse")
	}

	// Compute witness
	witnessValue := new(bn256.G1).ScalarMult(acc.Value, inv)

	return &Witness{Value: witnessValue}, nil
}

// NonMembershipWitness represents a proof that an element is not in the accumulator
type NonMembershipWitness struct {
	D *bn256.G1 // Helper value
	V *big.Int  // Helper value
}

// Verify verifies the witness by checking the element is not part of the accumulator
func (w NonMembershipWitness) Verify(acc *Accumulator, elem *Element, pk *PublicKey) bool {
	// For a valid non-membership witness (d, v), we verify:
	// e(acc, g2) = e(g1^v, g2) * e(d, g2^α * g2^y)
	// where y is the element we're proving non-membership for

	// Calculate g2^y
	g2y := new(bn256.G2).ScalarMult(pk.G2, elem.X)

	// Calculate g2^α * g2^y
	alphaPlusY := new(bn256.G2).Add(pk.Alpha, g2y)

	// Calculate e(g1^v, g2)
	g1v := new(bn256.G1).ScalarBaseMult(w.V)
	pair1 := bn256.Pair(g1v, pk.G2)

	// Calculate e(d, g2^α * g2^y)
	pair2 := bn256.Pair(w.D, alphaPlusY)

	// Multiply the pairings
	rhs := new(bn256.GT).Add(pair1, pair2)

	// Calculate e(acc, g2)
	lhs := bn256.Pair(acc.Value, pk.G2)

	return lhs.String() == rhs.String()
}

// func (w NonMembershipWitness) ZkProof(acc *Accumulator, elem *Element, pk *PublicKey) (*NonMembershipProof, error) {
// 	// Generate random value for the proof
// 	r, err := rand.Int(rand.Reader, bn256.Order)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate random value: %v", err)
// 	}

// 	// Compute commitment T = e(g1, g2)^r
// 	g1r := new(bn256.G1).ScalarBaseMult(r)
// 	T := bn256.Pair(g1r, pk.G2)

// 	// Generate challenge using public values
// 	challengeInput := []byte{}
// 	challengeInput = append(challengeInput, acc.Value.Marshal()...)
// 	challengeInput = append(challengeInput, elem.Value.Marshal()...)
// 	challengeInput = append(challengeInput, T.Marshal()...)
// 	challenge := new(big.Int).SetBytes(challengeInput)
// 	challenge.Mod(challenge, bn256.Order)

// 	// Compute response S = r + challenge * v
// 	S := new(big.Int).Mul(challenge, w.V)
// 	S.Add(S, r)
// 	S.Mod(S, bn256.Order)

// 	return &NonMembershipProof{
// 		T: T,
// 		S: S,
// 		D: w.D,
// 	}, nil
// }

// GenerateNonMembershipWitness generates a proof that an element is not in the accumulator
func GenerateNonMembershipWitness(acc *Accumulator, sk *SecretKey, elem *Element) (*NonMembershipWitness, error) {
	// For an element y that is not in the accumulator,
	// we need to find (d, v) such that acc = g^v * d^(y + α)

	// Calculate (y + α)
	sum := new(big.Int).Add(elem.X, sk.Alpha)
	sum.Mod(sum, bn256.Order)

	// Generate random value for v
	v, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %v", err)
	}

	// Calculate g^v
	gv := new(bn256.G1).ScalarBaseMult(v)

	// Calculate acc * (g^v)^(-1)
	gvInv := new(bn256.G1).Neg(gv)
	temp := new(bn256.G1).Add(acc.Value, gvInv)

	// Calculate d = (acc/g^v)^(1/(y + α))
	sumInv := new(big.Int).ModInverse(sum, bn256.Order)
	if sumInv == nil {
		return nil, fmt.Errorf("failed to compute inverse")
	}
	d := new(bn256.G1).ScalarMult(temp, sumInv)

	// Verify: acc = g^v * d^(y + α)
	dPowSum := new(bn256.G1).ScalarMult(d, sum)
	result := new(bn256.G1).Add(gv, dPowSum)

	if result.String() != acc.Value.String() {
		return nil, fmt.Errorf("invalid witness generated")
	}

	return &NonMembershipWitness{
		D: d,
		V: v,
	}, nil
}
