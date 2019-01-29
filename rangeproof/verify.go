package rangeproof

import (
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

func Verify(proof *Proof) error{
	R := new(HashR)
	e_0 := FP256BN.FromBytes(proof.E_0)
	H := EcpFromProto(proof.H)
	var Com []*FP256BN.ECP
	var S   []*FP256BN.BIG
	for i := 0; i < Size; i++ {
		Com = append(Com,EcpFromProto(proof.Com[i]))
		S = append(S,FP256BN.FromBytes(proof.S[i]))
	}

	//对于i∈{0,n-1}，计算e_i1 = H(s_i1·G-e_i0·[C_i-j*m^i·H])
	for i := 0; i < Size; i++ {
		jmiH := J_mi_H(H,1,2,i)
		C_i := Com[i]
		C_i.Sub(jmiH)
		temp1 := C_i.Mul(e_0)
		Gs := GenG1.Mul(S[i])
		Gs.Sub(temp1)
		HashData1 := make([]byte,2*FieldBytes+1)
		index1 := 0
		index1 = appendBytesG1(HashData1,index1,Gs)
		e_i1 := HashModOrder(HashData1)
		R_i := Com[i].Mul(e_i1)
		R.R = append(R.R,R_i)
	}

	//计算e_0
	HashData2 := make([]byte,Size*(2*FieldBytes+1))
	index2 := 0
	for i := 0; i < Size; i++ {
		index2 = appendBytesG1(HashData2,index2,R.R[i])
	}
	e_0_Prime := HashModOrder(HashData2)

	//判断e_0 == e_0'是否成立
	if e_0 == e_0_Prime {
		return errors.Errorf("rangeproof验证不通过！")
	}

	return nil
}
