/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	"bytes"
	"testing"
	"time"

	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/stretchr/testify/assert"
)

func TestIdemix(t *testing.T) {
	AttributeNames := []string{"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"}
	attrs := make([]*FP256BN.BIG, len(AttributeNames))
	for i := range AttributeNames {
		attrs[i] = FP256BN.NewBIGint(i)
	}

	// Test issuer key generation
	t1 := time.Now()
	rng, err := GetRand()
	if err != nil {
		t.Fatalf("Error getting rng: \"%s\"", err)
		return
	}
	// Create a new key pair
	key, err := NewIssuerKey(AttributeNames, rng)
	if err != nil {
		t.Fatalf("Issuer key generation should have succeeded but gave error \"%s\"", err)
		return
	}

	// Check that the key is valid
	err = key.GetIPk().Check()
	if err != nil {
		t.Fatalf("Issuer public key should be valid")
		return
	}

	// Make sure Check() is invalid for aF public key with invalid proof
	proofC := key.IPk.GetProofC()
	key.IPk.ProofC = BigToBytes(RandModOrder(rng))
	assert.Error(t, key.IPk.Check(), "public key with broken zero-knowledge proof should be invalid")

	// Make sure Check() is invalid for a public key with incorrect number of HAttrs
	hAttrs := key.IPk.GetHAttrs()
	key.IPk.HAttrs = key.IPk.HAttrs[:0]
	assert.Error(t, key.IPk.Check(), "public key with incorrect number of HAttrs should be invalid")
	key.IPk.HAttrs = hAttrs

	// Restore IPk to be valid
	key.IPk.ProofC = proofC
	h := key.IPk.GetHash()
	assert.NoError(t, key.IPk.Check(), "restored public key should be valid")
	assert.Zero(t, bytes.Compare(h, key.IPk.GetHash()), "IPK hash changed on ipk Check")

	// Create public with duplicate attribute names should fail
	_, err = NewIssuerKey([]string{"Attr1", "Attr2", "Attr1"}, rng)
	assert.Error(t, err, "issuer key generation should fail with duplicate attribute names")

	phase1 := time.Since(t1)
	println("Issuer key generation takes:",phase1/1e6,"ms")

	//Create group tracing key and group public key
	t2 := time.Now()

	GroupKeys, err := NewGroupKey(rng)
	if err != nil {
		t.Fatalf("Group key generation should have succeeded but gave error \"%s\"", err)
		return
	}

	phase2 := time.Since(t2)
	println("Group key generation takes:",phase2/1e6,"ms")

	//Create user's private keys
	t3 := time.Now()

	UserKeys, err := Registration(key, rng)
	if err != nil {
		t.Fatalf("User' private keys should be valid")
		return
	}

	phase3 := time.Since(t3)
	println("Generating user's key pair takes:",phase3/1e6,"ms")

	// Test issuance
	t4 := time.Now()
	sk := RandModOrder(rng)
	randCred := RandModOrder(rng)
	ni := RandModOrder(rng)
	m := NewCredRequest(sk, randCred, ni, key.IPk, rng)

	cred, err := NewCredential(key, m, attrs, rng)
	assert.NoError(t, err, "Failed to issue a credential: \"%s\"", err)

	cred.Complete(randCred)

	assert.NoError(t, cred.Ver(sk, key.IPk), "credential should be valid")

	phase4 := time.Since(t4)
	println("Generating a credential takes:",phase4/1e6,"ms")

	// Issuing a credential with the incorrect amount of attributes should fail
	_, err = NewCredential(key, m, []*FP256BN.BIG{}, rng)
	assert.Error(t, err, "issuing a credential with the incorrect amount of attributes should fail")

	// Breaking the ZK proof of the CredRequest should make it invalid
	proofC = m.GetProofC()
	m.ProofC = BigToBytes(RandModOrder(rng))
	assert.Error(t, m.Check(key.IPk), "CredRequest with broken ZK proof should not be valid")

	// Creating a credential from a broken CredRequest should fail
	_, err = NewCredential(key, m, attrs, rng)
	assert.Error(t, err, "creating a credential from an invalid CredRequest should fail")
	m.ProofC = proofC

	// A credential with nil attribute should be invalid
	attrsBackup := cred.GetAttrs()
	cred.Attrs = [][]byte{nil, nil, nil, nil, nil}
	assert.Error(t, cred.Ver(sk, key.IPk), "credential with nil attribute should be invalid")
	cred.Attrs = attrsBackup

	// Test signing no disclosure
	t5 := time.Now()
	Nym, RandNym := MakeNym(sk, key.IPk, rng)

	disclosure := []byte{0, 0, 0, 0, 0}
	msg := []byte{1, 2, 3, 4, 5}
	sig, err := NewSignature(cred, sk, Nym, RandNym, key.IPk, GroupKeys.GPK,UserKeys,disclosure, msg, rng)
	assert.NoError(t, err)

	err = sig.Ver(disclosure, key.IPk, GroupKeys.GPK,msg,nil)
	if err != nil {
		t.Fatalf("Signature should be valid but verification returned error: %s", err)
		return
	}

	// Test signing selective disclosure
	disclosure = []byte{0, 1, 1, 1, 1}
	sig, err = NewSignature(cred, sk, Nym, RandNym, key.IPk,GroupKeys.GPK,UserKeys, disclosure, msg, rng)
	assert.NoError(t, err)

	phase5 := time.Since(t5)
	println("Generating a signature takes:",phase5/1e6, "ms")

	t6 := time.Now()
	err = sig.Ver(disclosure, key.IPk, GroupKeys.GPK,msg, attrs)
	if err != nil {
		t.Fatalf("Signature should be valid but verification returned error: %s", err)
		return
	}
	phase6 := time.Since(t6)
	println("Verifying a signature takes:",phase6/1e6, "ms")

	//Test Tracing
	t7 := time.Now()

    k, err := Tracing(sig, GroupKeys.TK)

	if err != nil {
		t.Fatalf("Tracing should be invalid: %s", err)
		return
	}

	k1 := EcpFromProto(k.Ax)
	uk2 := EcpFromProto(UserKeys.UK2)
    if !k1.Equals(uk2) {
    	t.Fatalf("Tracing should be valid but gave error \"%s\"")
    	return
	}

	phase7 := time.Since(t7)
	println("Tracing takes:",phase7/1e6, "ms")
	
}