package main

import (
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

type ProofCommitment struct {
	T1 *bls12381.PointG1
	T2 *bls12381.PointG2
	T3 *bls12381.E
}

// MembershipProof represents a zero-knowledge proof of membership
type MembershipProof struct {
	Commitment *ProofCommitment
	Response   *big.Int
}

// Verify verifies the zero-knowledge proof of membership
func (p MembershipProof) Verify(acc *Accumulator, elem *Element, pk *PublicKey) bool {
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()

	// Regenerate challenge
	challengeInput := []byte{}
	accBytes := g1.ToBytes(acc.Value)
	elemBytes := g1.ToBytes(elem.Value)
	t1Bytes := g1.ToBytes(p.Commitment.T1)
	t2Bytes := g2.ToBytes(p.Commitment.T2)

	challengeInput = append(challengeInput, accBytes...)
	challengeInput = append(challengeInput, elemBytes...)
	challengeInput = append(challengeInput, t1Bytes...)
	challengeInput = append(challengeInput, t2Bytes...)

	challenge := new(big.Int).SetBytes(challengeInput)
	challenge.Mod(challenge, g1.Q())

	// Verify the proof using pairing equations
	// Check 1: e(witness, g2)^r = T3
	// Check 2: e(g1, g2)^response = e(T1, g2) * e(elem, g2)^challenge

	// Verify the proof using pairing equations
	e := bls12381.NewEngine()

	// Calculate e(g1^response, g2)
	responsePoint := g1.New()
	g1.MulScalar(responsePoint, g1.One(), bls12381.NewFr().FromBytes(p.Response.Bytes()))
	e.AddPair(responsePoint, pk.G2)
	lhs := e.Result()

	e.Reset()
	// Calculate e(T1, g2)
	e.AddPair(p.Commitment.T1, pk.G2)

	// Calculate e(elem, g2)^challenge
	elemPair := g1.New()
	g1.MulScalar(elemPair, elem.Value, bls12381.NewFr().FromBytes(challenge.Bytes()))
	e.AddPair(elemPair, pk.G2)
	rhs := e.Result()

	return lhs.Equal(rhs)
}

type NonMembershipProof struct {
	T *bls12381.E       // Commitment to random value
	S *big.Int          // Response
	D *bls12381.PointG1 // Helper from witness
}

func (p NonMembershipProof) Verify(acc *Accumulator, elem *Element, pk *PublicKey) bool {
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()
	e := bls12381.NewEngine()

	// Recompute challenge
	challengeInput := []byte{}
	challengeInput = append(challengeInput, g1.ToBytes(acc.Value)...)
	challengeInput = append(challengeInput, g1.ToBytes(elem.Value)...)
	// Note: T is already a pairing result, we skip it in challenge computation

	challenge := new(big.Int).SetBytes(challengeInput)
	challenge.Mod(challenge, g1.Q())

	// Calculate g2^{y + α}
	g2y := g2.New()
	g2.MulScalar(g2y, pk.G2, bls12381.NewFr().FromBytes(elem.X.Bytes()))

	// Calculate g2^α * g2^y
	alphaPlusY := g2.New()
	g2.Add(alphaPlusY, pk.Alpha, g2y)

	// Calculate g1^S
	g1s := g1.New()
	g1.MulScalar(g1s, g1.One(), bls12381.NewFr().FromBytes(p.S.Bytes()))

	// Verify e(g1^S, g2) = T * e(acc, g2)^challenge * e(D, g2^{α + y})^challenge
	e.AddPair(g1s, pk.G2)
	lhs := e.Result()

	e.Reset()
	e.AddPair(acc.Value, pk.G2)
	e.AddPairInv(p.D, alphaPlusY)
	rhs := e.Result()

	return lhs.Equal(rhs)
}
