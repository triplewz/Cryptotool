/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dkmxier

import (
	"crypto/rand"
	"crypto/sha256"

	"github.com/milagro-crypto/amcl/version3/go/amcl"
	"github.com/milagro-crypto/amcl/version3/go/amcl/SECP256K1"
	"github.com/pkg/errors"
)

type ECP struct {
	X   []byte
	Y   []byte
}


// GenG1 is a generator of Group G1
var GenG1 = SECP256K1.NewECPbigs(
	SECP256K1.NewBIGints(SECP256K1.CURVE_Gx),
	SECP256K1.NewBIGints(SECP256K1.CURVE_Gy))

// GroupOrder is the order of the groups
var GroupOrder = SECP256K1.NewBIGints(SECP256K1.CURVE_Order)

// FieldBytes is the bytelength of the group order
var FieldBytes = int(SECP256K1.MODBYTES)

// RandModOrder returns a random element in 0, ..., GroupOrder-1
func RandModOrder(rng *amcl.RAND) *SECP256K1.BIG {
	// curve order q
	q := SECP256K1.NewBIGints(SECP256K1.CURVE_Order)

	// Take random element in Zq
	return SECP256K1.Randomnum(q, rng)
}

// HashModOrder hashes data into 0, ..., GroupOrder-1
func HashModOrder(data []byte) *SECP256K1.BIG {
	digest := sha256.Sum256(data)
	digestBig := SECP256K1.FromBytes(digest[:])
	digestBig.Mod(GroupOrder)
	return digestBig
}

func appendBytesG1(data []byte, index int, E *SECP256K1.ECP) int {
	length := 2*FieldBytes + 1
	E.ToBytes(data[index : index+length],true)
	return index + length
}

func appendBytesBig(data []byte, index int, B *SECP256K1.BIG) int {
	length := FieldBytes
	B.ToBytes(data[index : index+length])
	return index + length
}
func appendBytesString(data []byte, index int, s string) int {
	bytes := []byte(s)
	copy(data[index:], bytes)
	return index + len(bytes)
}

// BigToBytes takes an *amcl.BIG and returns a []byte representation
func BigToBytes(big *SECP256K1.BIG) []byte {
	ret := make([]byte, FieldBytes)
	big.ToBytes(ret)
	return ret
}

// EcpToProto converts a *amcl.ECP into the proto struct *ECP
func EcpToProto(p *SECP256K1.ECP) *ECP {
	return &ECP{
		BigToBytes(p.GetX()),
		BigToBytes(p.GetY())}
}


// EcpFromProto converts a proto struct *ECP into an *amcl.ECP
func EcpFromProto(p *ECP) *SECP256K1.ECP {
	return SECP256K1.NewECPbigs(SECP256K1.FromBytes(p.X), SECP256K1.FromBytes(p.Y))
}

/*
// Ecp2ToProto converts a *amcl.ECP2 into the proto struct *ECP2
func Ecp2ToProto(p *SECP256K1.ECP2) *ECP2 {
	return &ECP2{
		BigToBytes(p.GetX().GetA()),
		BigToBytes(p.GetX().GetB()),
		BigToBytes(p.GetY().GetA()),
		BigToBytes(p.GetY().GetB())}
}

// Ecp2FromProto converts a proto struct *ECP2 into an *amcl.ECP2
func Ecp2FromProto(p *ECP2) *SECP256K1.ECP2 {
	return SECP256K1.NewECP2fp2s(
		SECP256K1.NewFP2bigs(SECP256K1.FromBytes(p.GetXA()), SECP256K1.FromBytes(p.GetXB())),
		SECP256K1.NewFP2bigs(SECP256K1.FromBytes(p.GetYA()), SECP256K1.FromBytes(p.GetYB())))
}
*/

// GetRand returns a new *amcl.RAND with a fresh seed
func GetRand() (*amcl.RAND, error) {
	seedLength := 32
	b := make([]byte, seedLength)
	_, err := rand.Read(b)
	if err != nil {
		return nil, errors.Wrap(err, "error getting randomness for seed")
	}
	rng := amcl.NewRAND()
	rng.Clean()
	rng.Seed(seedLength, b)
	return rng, nil
}

// Modadd takes input BIGs a, b, m, and returns a+b modulo m
func Modadd(a, b, m *SECP256K1.BIG) *SECP256K1.BIG {
	c := a.Plus(b)
	c.Mod(m)
	return c
}

// Modsub takes input BIGs a, b, m and returns a-b modulo m
func Modsub(a, b, m *SECP256K1.BIG) *SECP256K1.BIG {
	return Modadd(a, SECP256K1.Modneg(b, m), m)
}
