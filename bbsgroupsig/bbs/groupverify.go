package bbsgroupsig

import (
	"github.com/cloudflare/bn256"
	"github.com/pkg/errors"
	"math/big"
)

//验证群签名
func GroupVerify(groupSig *GroupSignature,gpk *GroupPublicKey, message []byte) error{
	//转换签名数据格式
	T1 := groupSig.T1
	T2 := groupSig.T2
	T3 := groupSig.T3
	c := new(big.Int).SetBytes(groupSig.ProofC)
	sAlpha := new(big.Int).SetBytes(groupSig.ProofSalpha)
	sBeta := new(big.Int).SetBytes(groupSig.ProofSbeta)
	sx := new(big.Int).SetBytes(groupSig.ProofSx)
	sDelta1 := new(big.Int).SetBytes(groupSig.ProofSdelta1)
	sDelta2 := new(big.Int).SetBytes(groupSig.ProofSdelta2)
	temp1 := new(big.Int).Add(sAlpha,sBeta)
	temp1.Mod(temp1,bn256.Order)
	temp2 := new(big.Int).Add(sDelta1,sDelta2)
	temp2.Mod(temp2,bn256.Order)

	//群公钥
	U := gpk.U
	V := gpk.V
	H := gpk.H
	W := gpk.W

	//计算R1,R2,R3,R4,R5
	Us := new(bn256.G1).ScalarMult(U,sAlpha)
	Tc1 := new(bn256.G1).ScalarMult(T1,c)
	Tc1_neg := new(bn256.G1).Neg(Tc1)
	R1 := new(bn256.G1).Add(Us,Tc1_neg)

	Vs := new(bn256.G1).ScalarMult(V,sBeta)
	Tc2 := new(bn256.G1).ScalarMult(T2,c)
	Tc2_neg := new(bn256.G1).Neg(Tc2)
	R2 := new(bn256.G1).Add(Vs,Tc2_neg)

	//R3为GT中元素
	e1 := bn256.Pair(T3,bn256.Gen2)

	e2 := new(bn256.GT).ScalarMult(e1,sx)

	e3 := bn256.Pair(H,W)
	temp1_neg := new(big.Int).Neg(temp1)
	temp1_neg.Mod(temp1_neg,bn256.Order)
	e4 := new(bn256.GT).ScalarMult(e3,temp1_neg)

	e_mul1 := new(bn256.GT).Add(e2,e4)

	e5 := bn256.Pair(H,bn256.Gen2)
	temp2_neg := new(big.Int).Neg(temp2)
	temp2_neg.Mod(temp2_neg,bn256.Order)
	e6 := new(bn256.GT).ScalarMult(e5,temp2_neg)

	e_mul2 := new(bn256.GT).Add(e_mul1,e6)

	e7 := bn256.Pair(T3,W)
	e8 := new(bn256.GT).ScalarMult(e7,c)

	e_mul3 := new(bn256.GT).Add(e_mul2,e8)

	c_neg := new(big.Int).Neg(c)
	c_neg.Mod(c_neg,bn256.Order)
	e9 := new(bn256.GT).ScalarBaseMult(c_neg)

	R3 := new(bn256.GT).Add(e_mul3,e9)

	Ts1 := new(bn256.G1).ScalarMult(T1,sx)
	Usd1 := new(bn256.G1).ScalarMult(U,sDelta1)
	Usd1_neg := new(bn256.G1).Neg(Usd1)
	R4 := new(bn256.G1).Add(Ts1,Usd1_neg)

	Ts2 := new(bn256.G1).ScalarMult(T2,sx)
	Usd2 := new(bn256.G1).ScalarMult(V,sDelta2)
	Usd2_neg := new(bn256.G1).Neg(Usd2)
	R5 := new(bn256.G1).Add(Ts2,Usd2_neg)

	//计算挑战值c'，哈希数据包括
	//7个G1元素，每个长度为2*Fieldbytes,1个GT元素，长度为12*Fieldbytes
	//一个消息message
	var hashData []byte
	buf1 := T1.Marshal()
	hashData = append(hashData,buf1...)
	buf2 := T2.Marshal()
	hashData = append(hashData,buf2...)
	buf3 := T3.Marshal()
	hashData = append(hashData,buf3...)
	buf4 := R1.Marshal()
	hashData = append(hashData,buf4...)
	buf5 := R2.Marshal()
	hashData = append(hashData,buf5...)
	buf6 := R3.Marshal()
	hashData = append(hashData,buf6...)
	buf7 := R4.Marshal()
	hashData = append(hashData,buf7...)
	buf8 := R5.Marshal()
	hashData = append(hashData,buf8...)

	hashData = append(hashData,message...)
	cPrime := HashModOrder(hashData)

	//判断c=c'是否相等
	if c.Cmp(cPrime) != 0 {
		return errors.Errorf("The group signature is invalid!")
	}

	return nil
}