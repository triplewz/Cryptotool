package rangeproof

import (
	"github.com/milagro-crypto/amcl/version3/go/amcl/SECP256K1"
	"github.com/pkg/errors"
)

//验证rangeproof（v是否属于[0,2^32-1]）
func Verify(proof *Proof) error{
	R := new(HashR)
	e_0 := SECP256K1.FromBytes(proof.E_0)
	H := EcpFromProto(proof.H)

	//对于i∈{0,n-1}，计算e_i1 = H(s_i1·G-e_i0·[C_i-j*m^i·H])
	for i := 0; i < Size; i++ {
		jmiH := J_mi_H(H,1,2,i)
		C_i := EcpFromProto(proof.Com[i])
		C_i.Sub(jmiH)
		temp1 := C_i.Mul(e_0)
		Gs := GenG1.Mul(SECP256K1.FromBytes(proof.S[i]))
		Gs.Sub(temp1)
		hashData1 := make([]byte,2*FieldBytes+1)
		index1 := 0
		index1 = appendBytesG1(hashData1,index1,Gs)
		e_i1 := HashModOrder(hashData1)
		R_i := EcpFromProto(proof.Com[i]).Mul(e_i1)
		R.R = append(R.R,R_i)
	}

	//计算e_0
	hashData2 := make([]byte,Size*(2*FieldBytes+1))
	index2 := 0
	for i := 0; i < Size; i++ {
		index2 = appendBytesG1(hashData2,index2,R.R[i])
	}
	e_0_Prime := HashModOrder(hashData2)

	//判断e_0 == e_0'是否成立
	if *e_0 == *e_0_Prime {
		return errors.Errorf("rangeproof验证不通过！")
	}

	return nil
}
