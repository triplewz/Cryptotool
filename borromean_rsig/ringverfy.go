package borromean_rsig

import (
	"github.com/pkg/errors"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
)

//环签名验证
func RingSigVerfy(ringSig *RingSig, signPubKey *RingPK,m []byte) error {
	if ringSig == nil || signPubKey == nil {
		return errors.Errorf("环签名格式错误")
	}

	hashValuePrime := new(HashValue)
	comPrime := new(Com)
	var G1Prime *FP256BN.ECP

	//用随机值填充hashValuePrime
	for i := 0; i < ringSig.N; i++ {
		var fillValue []*FP256BN.BIG
		for j := 0; j < ringSig.M; j++{
			fillValue = append(fillValue,FP256BN.FromBytes(ringSig.E_0))
		}
		hashValuePrime.E = append(hashValuePrime.E,fillValue)
	}

	//计算哈希值R
	for i := 0; i < ringSig.N ; i++ {
		hashValuePrime.E[i][0] = FP256BN.FromBytes(ringSig.E_0)
		for j := 0; j < ringSig.M - 1; j++{
			G1Prime = GenG1.Mul(FP256BN.FromBytes(ringSig.S[i][j]))
			G1Prime.Sub(EcpFromProto(signPubKey.PK[i][j]).Mul(hashValuePrime.E[i][j]))
			hashValuePrime.E[i][j+1] = BorromeanHash(m,G1Prime,i,j)
		}
		G1Prime = GenG1.Mul(FP256BN.FromBytes(ringSig.S[i][ringSig.M-1]))
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
	if *e_0 != *FP256BN.FromBytes(ringSig.E_0){
		return errors.Errorf("签名无效")
	}

	return nil
}