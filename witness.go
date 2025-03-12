package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

// Witness is the membership witness
type Witness struct {
	Value *bls12381.PointG1
}

// Verify verifies the witness by checking the element is part of the accumulator
func (w Witness) Verify(acc *Accumulator, elem *Element, pk *PublicKey) bool {
	// e(w, g2^α) * e(g1^x, g2) = e(acc, g2)
	// where w is the witness, x is the element, acc is the accumulator value

	e := bls12381.NewEngine()

	// Calculate e(w, g2^α)
	e.AddPair(w.Value, pk.Alpha)

	// Calculate e(g1^x, g2)
	e.AddPair(elem.Value, pk.G2)
	lhs := e.Result()

	e.Reset()

	// Calculate e(acc, g2)
	e.AddPair(acc.Value, pk.G2)
	rhs := e.Result()

	// Compare the pairing results directly
	return lhs.Equal(rhs)
}

// ZkProof creates a zero-knowledge proof of membership
func (w Witness) ZkProof(acc *Accumulator, elem *Element, pk *PublicKey) (*MembershipProof, error) {
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()

	// Generate random value for blinding
	r, err := rand.Int(rand.Reader, g1.Q())
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %v", err)
	}

	// Create commitments
	t1 := g1.New()
	g1.MulScalar(t1, w.Value, bls12381.NewFr().FromBytes(r.Bytes()))

	t2 := g2.New()
	g2.MulScalar(t2, pk.G2, bls12381.NewFr().FromBytes(r.Bytes()))

	e := bls12381.NewEngine()
	e.AddPair(w.Value, pk.G2)
	t3 := e.Result()

	commitment := &ProofCommitment{
		T1: t1,
		T2: t2,
		T3: t3,
	}

	// Generate challenge using hash of all public values
	challengeInput := []byte{}
	accBytes := g1.ToBytes(acc.Value)
	elemBytes := g1.ToBytes(elem.Value)
	t1Bytes := g1.ToBytes(t1)
	t2Bytes := g2.ToBytes(t2)

	challengeInput = append(challengeInput, accBytes...)
	challengeInput = append(challengeInput, elemBytes...)
	challengeInput = append(challengeInput, t1Bytes...)
	challengeInput = append(challengeInput, t2Bytes...)

	challenge := new(big.Int).SetBytes(challengeInput)
	challenge.Mod(challenge, g1.Q())

	// Calculate response = r + challenge * x
	response := new(big.Int).Mul(challenge, elem.X)
	response.Add(response, r)
	response.Mod(response, g1.Q())

	return &MembershipProof{
		Commitment: commitment,
		Response:   response,
	}, nil
}

// GenerateWitness generates a membership witness for the given element
func GenerateWitness(acc *Accumulator, sk *SecretKey, elem *Element) (*Witness, error) {
	g1 := bls12381.NewG1()

	// Witness computation: w = acc^(1/(x + α))
	// where x is the element value and α is the secret key

	// Calculate (x + α)
	sum := new(big.Int).Add(elem.X, sk.Alpha)
	sum.Mod(sum, g1.Q())

	// Calculate modular multiplicative inverse
	inv := new(big.Int).ModInverse(sum, g1.Q())
	if inv == nil {
		return nil, fmt.Errorf("failed to compute inverse")
	}

	// Compute witness
	witnessValue := g1.New()
	g1.MulScalar(witnessValue, acc.Value, bls12381.NewFr().FromBytes(inv.Bytes()))

	return &Witness{Value: witnessValue}, nil
}

// NonMembershipWitness represents a proof that an element is not in the accumulator
type NonMembershipWitness struct {
	D *bls12381.PointG1 // Helper value
	V *big.Int          // Helper value
}

// Verify verifies the witness by checking the element is not part of the accumulator
func (w NonMembershipWitness) Verify(acc *Accumulator, elem *Element, pk *PublicKey) bool {
	g1 := bls12381.NewG1()
	g2 := bls12381.NewG2()

	// For a valid non-membership witness (d, v), we verify:
	// e(acc, g2) = e(g1^v, g2) * e(d, g2^α * g2^y)
	// where y is the element we're proving non-membership for

	// Calculate g2^y
	g2y := g2.New()
	g2.MulScalar(g2y, pk.G2, bls12381.NewFr().FromBytes(elem.X.Bytes()))

	// Calculate g2^α * g2^y
	alphaPlusY := g2.New()
	g2.Add(alphaPlusY, pk.Alpha, g2y)

	// Calculate g1^v
	g1v := g1.New()
	g1.MulScalar(g1v, g1.One(), bls12381.NewFr().FromBytes(w.V.Bytes()))

	e := bls12381.NewEngine()
	e.AddPair(g1v, pk.G2)
	e.AddPair(w.D, alphaPlusY)
	rhs := e.Result()

	e.Reset()
	e.AddPair(acc.Value, pk.G2)
	lhs := e.Result()

	return lhs.Equal(rhs)
}

func (w NonMembershipWitness) ZkProof(acc *Accumulator, elem *Element, pk *PublicKey) (*NonMembershipProof, error) {
	g1 := bls12381.NewG1()
	e := bls12381.NewEngine()

	// Generate random value for the proof
	r, err := rand.Int(rand.Reader, g1.Q())
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %v", err)
	}

	// Compute commitment T = e(g1, g2)^r
	g1r := g1.New()
	g1.MulScalar(g1r, g1.One(), bls12381.NewFr().FromBytes(r.Bytes()))
	e.AddPair(g1r, pk.G2)
	T := e.Result()

	// Generate challenge using public values
	challengeInput := []byte{}
	challengeInput = append(challengeInput, g1.ToBytes(acc.Value)...)
	challengeInput = append(challengeInput, g1.ToBytes(elem.Value)...)
	challengeInput = append(challengeInput, g1.ToBytes(g1r)...)

	challenge := new(big.Int).SetBytes(challengeInput)
	challenge.Mod(challenge, g1.Q())

	// Compute response S = r + challenge * v
	S := new(big.Int).Mul(challenge, w.V)
	S.Add(S, r)
	S.Mod(S, g1.Q())

	return &NonMembershipProof{
		T: T,
		S: S,
		D: w.D,
	}, nil
}

// GenerateNonMembershipWitness generates a proof that an element is not in the accumulator
func GenerateNonMembershipWitness(acc *Accumulator, sk *SecretKey, elem *Element) (*NonMembershipWitness, error) {
	g1 := bls12381.NewG1()

	// For an element y that is not in the accumulator,
	// we need to find (d, v) such that acc = g^v * d^(y + α)

	// Calculate (y + α)
	sum := new(big.Int).Add(elem.X, sk.Alpha)
	sum.Mod(sum, g1.Q())

	// Generate random value for v
	v, err := rand.Int(rand.Reader, g1.Q())
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %v", err)
	}

	// Calculate g^v
	gv := g1.New()
	g1.MulScalar(gv, g1.One(), bls12381.NewFr().FromBytes(v.Bytes()))

	// Calculate acc * (g^v)^(-1)
	gvInv := g1.New()
	g1.Neg(gvInv, gv)
	temp := g1.New()
	g1.Add(temp, acc.Value, gvInv)

	// Calculate d = (acc/g^v)^(1/(y + α))
	sumInv := new(big.Int).ModInverse(sum, g1.Q())
	if sumInv == nil {
		return nil, fmt.Errorf("failed to compute inverse")
	}

	d := g1.New()
	g1.MulScalar(d, temp, bls12381.NewFr().FromBytes(sumInv.Bytes()))

	// Verify: acc = g^v * d^(y + α)
	dPowSum := g1.New()
	g1.MulScalar(dPowSum, d, bls12381.NewFr().FromBytes(sum.Bytes()))
	result := g1.New()
	g1.Add(result, gv, dPowSum)

	if !g1.Equal(result, acc.Value) {
		return nil, fmt.Errorf("invalid witness generated")
	}

	return &NonMembershipWitness{
		D: d,
		V: v,
	}, nil
}
