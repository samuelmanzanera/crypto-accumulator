package main

import (
	"fmt"
	"math/big"

	bls12381 "github.com/kilic/bls12-381"
)

func setup() (*Accumulator, *SecretKey, *PublicKey, error) {
	sk, err := NewSecretKey()
	if err != nil {
		return nil, nil, nil, err
	}

	acc := NewAccumulator()
	publicKey := sk.ToPublicKey()

	return &acc, sk, &publicKey, nil
}

func main() {
	// Setup
	acc, sk, pk, err := setup()
	if err != nil {
		panic(err)
	}

	// Create element using hash
	message := []byte("test_element")
	x := HashToInt(message)
	g1 := bls12381.NewG1()
	elemValue := g1.New()
	g1.MulScalar(elemValue, g1.One(), bls12381.NewFr().FromBytes(x.Bytes()))
	elem := &Element{
		Value: elemValue,
		X:     x,
	}

	acc.Add(sk, elem)

	// Generate witness
	witness_mem, err := GenerateWitness(acc, sk, elem)
	if err != nil {
		panic(err)
	}

	// Verify membership
	isMember := witness_mem.Verify(acc, elem, pk)
	if !isMember {
		panic("Membership for the expected should be valid")
	}
	fmt.Println("✓ Membership witness is valid for an accumulated element")

	// Create non-element using different hash
	nonMessage := []byte("non_member_element")
	y := HashToInt(nonMessage)
	nonelemValue := g1.New()

	g1.MulScalar(nonelemValue, g1.One(), bls12381.NewFr().FromBytes(y.Bytes()))
	nonelem := &Element{
		Value: nonelemValue,
		X:     y,
	}

	// Generate witness
	witness_mem_invalid, err := GenerateWitness(acc, sk, nonelem)
	if err != nil {
		panic(err)
	}

	// Verify membership
	isMember = witness_mem_invalid.Verify(acc, nonelem, pk)
	if isMember {
		panic("Membership for the non existing elem should not be valid")
	}
	fmt.Println("✓ Membership witness is invalid for an non accumulated element")

	// Generate non-membership witness
	nonMembershipWitness, err := GenerateNonMembershipWitness(acc, sk, nonelem)
	if err != nil {
		panic(err)
	}

	// Verify non-membership
	isNonMember := nonMembershipWitness.Verify(acc, nonelem, pk)
	if !isNonMember {
		panic("Non-membership verification failed")
	}
	fmt.Println("✓ NonMembership witness is valid for an non accumulated element")

	// This should fail for elements that are actually in the accumulator
	isNonMember = nonMembershipWitness.Verify(acc, elem, pk)
	if isNonMember {
		panic("Non-membership verification should fail for members")
	}
	fmt.Println("✓ NonMembership witness is invalid for an accumulated element")

	acc.Add(sk, nonelem)
	isNonMember = nonMembershipWitness.Verify(acc, elem, pk)
	if isNonMember {
		panic("Non-membership verification failed for nonelement added in the accumulator")
	}
	fmt.Println("✓ NonMembership witness is valid for an added non accumulated element")

	// Generate ZK proof of membership
	zkProof, err := witness_mem.ZkProof(acc, elem, pk)
	if err != nil {
		panic(err)
	}

	// Verify ZK proof
	isValidProof := zkProof.Verify(acc, elem, pk)
	if !isValidProof {
		panic("ZK proof verification failed")
	}
	fmt.Println("ZK proof verification successful!")

	fmt.Println("Testing invalid proof scenarios:")

	// Test 1: Tampered element value
	tamperedValue := g1.New()
	g1.MulScalar(tamperedValue, g1.One(), bls12381.NewFr().FromBytes(big.NewInt(43).Bytes()))
	tamperedElem := &Element{
		Value: tamperedValue, // Different value
		X:     elem.X,        // Same X value as the valid element
	}
	isValidProof = zkProof.Verify(acc, tamperedElem, pk)
	if isValidProof {
		panic("Proof verification should fail with tampered element")
	}
	fmt.Println("✓ Proof correctly failed for tampered element")

	// Test 2: Tampered proof response
	tamperedProof := &MembershipProof{
		Commitment: zkProof.Commitment,
		Response:   new(big.Int).Add(zkProof.Response, big.NewInt(1)), // Tampered response
	}
	isValidProof = tamperedProof.Verify(acc, elem, pk)
	if isValidProof {
		panic("Proof verification should fail with tampered response")
	}
	fmt.Println("✓ Proof correctly failed for tampered response")

	// Test 3: Wrong element trying to use valid proof
	wrongValue := g1.New()
	wrongX := new(big.Int).SetInt64(99)
	g1.MulScalar(wrongValue, g1.One(), bls12381.NewFr().FromBytes(wrongX.Bytes()))
	wrongElem := &Element{
		Value: wrongValue,
		X:     wrongX,
	}
	isValidProof = zkProof.Verify(acc, wrongElem, pk)
	if isValidProof {
		panic("Proof verification should fail with wrong element")
	}
	fmt.Println("✓ Proof correctly failed for wrong element")

	fmt.Println("All invalid membership proof tests passed successfully!")

	// // Generate ZK proof of membership
	// zkProofNonMem, err := nonMembershipWitness.ZkProof(acc, nonelem, pk)
	// if err != nil {
	// 	panic(err)
	// }

	// // Verify ZK proof
	// isValidProofNonMem := zkProofNonMem.Verify(acc, nonelem, pk)
	// if !isValidProofNonMem {
	// 	panic("ZK proof verification failed")
	// }
	// fmt.Println("ZK proof verification successful!")
}
