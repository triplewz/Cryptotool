package mpringsig

import (
	"github.com/milagro-crypto/amcl/version3/go/amcl/SECP256K1"
)

//环签名验证
func RingSigVerfy(ringSig *RingSig, signPubKey *RingPK,m []byte) bool {
	if ringSig == nil || signPubKey == nil {
		return false
	}

	hashValuePrime := new(HashValue)
	comPrime := new(Com)
	var G1Prime *SECP256K1.ECP

	hashValuePrime.E = make([][]*SECP256K1.BIG,ringSig.N)
	//计算哈希值R
	for i := 0; i < ringSig.N ; i++ {
		hashValuePrime.E[i] = make([]*SECP256K1.BIG,ringSig.M)
		hashValuePrime.E[i][0] = SECP256K1.FromBytes(ringSig.E_0)
		for j := 0; j < ringSig.M - 1; j++{
			G1Prime = GenG1.Mul(SECP256K1.FromBytes(ringSig.S[i][j]))
			G1Prime.Sub(EcpFromProto(signPubKey.PK[i][j]).Mul(hashValuePrime.E[i][j]))
			hashValuePrime.E[i][j+1] = BorromeanHash(m,G1Prime,i,j)
		}
		G1Prime = GenG1.Mul(SECP256K1.FromBytes(ringSig.S[i][ringSig.M-1]))
		G1Prime.Sub(EcpFromProto(signPubKey.PK[i][ringSig.M-1]).Mul(hashValuePrime.E[i][ringSig.M-1]))
		comPrime.R = append(comPrime.R,G1Prime)
	}

	//计算E_0'
	hashE := make([]byte,ringSig.N*(2*FieldBytes+1))
	index := 0
	for i :=0; i < ringSig.N; i++{
		index = appendBytesG1(hashE,index,comPrime.R[i])
	}
	e_0 := HashModOrder(hashE)

	//验证E_0'=E_0是否成立
	if *e_0 != *SECP256K1.FromBytes(ringSig.E_0){
		return false
	}

	return true
}