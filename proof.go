package main

import (
	"math/big"

	"github.com/cloudflare/bn256"
)

type ProofCommitment struct {
	T1 *bn256.G1
	T2 *bn256.G2
	T3 *bn256.GT
}

// MembershipProof represents a zero-knowledge proof of membership
type MembershipProof struct {
	Commitment *ProofCommitment
	Response   *big.Int
}

// Verify verifies the zero-knowledge proof of membership
func (p MembershipProof) Verify(acc *Accumulator, elem *Element, pk *PublicKey) bool {

	// Regenerate challenge
	challengeInput := []byte{}
	challengeInput = append(challengeInput, acc.Value.Marshal()...)
	challengeInput = append(challengeInput, elem.Value.Marshal()...)
	challengeInput = append(challengeInput, p.Commitment.T1.Marshal()...)
	challengeInput = append(challengeInput, p.Commitment.T2.Marshal()...)

	challenge := new(big.Int).SetBytes(challengeInput)
	challenge.Mod(challenge, bn256.Order)

	// Verify the proof using pairing equations
	// Check 1: e(witness, g2)^r = T3
	// Check 2: e(g1, g2)^response = e(T1, g2) * e(elem, g2)^challenge

	// Check 2
	lhs := bn256.Pair(new(bn256.G1).ScalarBaseMult(p.Response), pk.G2)

	temp1 := bn256.Pair(p.Commitment.T1, pk.G2)
	temp2 := bn256.Pair(elem.Value, pk.G2)
	temp2.ScalarMult(temp2, challenge)

	rhs := new(bn256.GT).Add(temp1, temp2)

	return lhs.String() == rhs.String()
}

// type NonMembershipProof struct {
// 	T *bn256.GT // Commitment to random value
// 	S *big.Int  // Response
// 	D *bn256.G1 // Helper from witness
// }

// func (p NonMembershipProof) Verify(acc *Accumulator, pk *PublicKey, elem *Element) bool {
// 	// Recompute challenge
// 	challengeInput := []byte{}
// 	challengeInput = append(challengeInput, acc.Value.Marshal()...)
// 	challengeInput = append(challengeInput, elem.Value.Marshal()...)
// 	challengeInput = append(challengeInput, p.T.Marshal()...)
// 	challenge := new(big.Int).SetBytes(challengeInput)
// 	challenge.Mod(challenge, bn256.Order)

// 	// Verify: e(g1^S, g2) == T * (e(acc, g2) / e(D, g2^{y + α}))^challenge

// 	// Compute LHS: e(g1^S, g2)
// 	g1s := new(bn256.G1).ScalarBaseMult(p.S)
// 	lhs := bn256.Pair(g1s, pk.G2)

// 	// Compute RHS components
// 	// e(acc, g2)
// 	accPair := bn256.Pair(acc.Value, pk.G2)

// 	// g2^{y + α} = g2^y * pk.Alpha
// 	g2y := new(bn256.G2).ScalarMult(pk.G2, elem.X)
// 	g2yAlpha := new(bn256.G2).Add(g2y, pk.Alpha)

// 	// e(D, g2^{y + α})
// 	dPair := bn256.Pair(p.D, g2yAlpha)

// 	// (e(acc, g2) / e(D, g2^{y + α})) = accPair * dPair^{-1}
// 	ratio := new(bn256.GT).Add(accPair, new(bn256.GT).Neg(dPair))

// 	// (ratio)^challenge
// 	ratioC := new(bn256.GT).ScalarMult(ratio, challenge)

// 	// T * ratioC
// 	rhs := new(bn256.GT).Add(p.T, ratioC)

// 	return lhs.String() == rhs.String()
// }
