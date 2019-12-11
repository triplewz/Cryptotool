package bbsgroupsig

import (
	"crypto/rand"
	"github.com/cloudflare/bn256"
	"github.com/pkg/errors"
	"math/big"
)

//所实现群签名方案为BBS群签名方案
//原文："Short Group Signatures"， https://link.springer.com/content/pdf/10.1007%2F978-3-540-28628-8_3.pdf.

type GroupSignature struct {
	T1                   *bn256.G1
	T2                   *bn256.G1
	T3                   *bn256.G1
	ProofC               []byte
	ProofSalpha          []byte
	ProofSbeta           []byte
	ProofSx              []byte
	ProofSdelta1         []byte
	ProofSdelta2         []byte
}

//用户生成群签名
func NewGroupSig(gpk *GroupPublicKey,uk *UserKey, message []byte)(*GroupSignature,error){
	if gpk == nil || uk == nil  {
		return nil, errors.Errorf("无法生成群签名：输入为空")
	}

	//签名
	//计算T1,T2,T3
	alpha,_ := rand.Int(rand.Reader,bn256.Order)
	beta,_ := rand.Int(rand.Reader,bn256.Order)

	U := gpk.U
	V := gpk.V
	H := gpk.H
	W := gpk.W
	x := new(big.Int).SetBytes(uk.UK1)
	Ax := uk.UK2

	T1 := new(bn256.G1).ScalarMult(U,alpha)
	T2 := new(bn256.G1).ScalarMult(V,beta)
	temp := new(big.Int).Add(alpha,beta)
	temp.Mod(temp,bn256.Order)
	Ht := new(bn256.G1).ScalarMult(H,temp)
	T3 := new(bn256.G1).Add(Ht,Ax)

	//计算R1,R2,R3,R4,R5
	delta1 := new(big.Int).Mul(alpha,x)
	delta1.Mod(delta1,bn256.Order)
	delta2 := new(big.Int).Mul(beta,x)
	delta2.Mod(delta2,bn256.Order)
	rAlpha,_ := rand.Int(rand.Reader,bn256.Order)
	rBeta,_ := rand.Int(rand.Reader,bn256.Order)
	rx,_ := rand.Int(rand.Reader,bn256.Order)
	rDelta1,_ := rand.Int(rand.Reader,bn256.Order)
	rDelta2,_ := rand.Int(rand.Reader,bn256.Order)
	temp1 := new(big.Int).Add(rAlpha,rBeta)
	temp1.Mod(temp1,bn256.Order)
	temp2 := new(big.Int).Add(rDelta1,rDelta2)
	temp2.Mod(temp2,bn256.Order)

	R1 := new(bn256.G1).ScalarMult(U,rAlpha)
	R2 := new(bn256.G1).ScalarMult(V,rBeta)

	//R3为GT中元素
	e1 := bn256.Pair(T3,bn256.Gen2)
	e2 := new(bn256.GT).ScalarMult(e1,rx)

	e3 := bn256.Pair(H,W)
	temp1_neg := new(big.Int).Neg(temp1)
	temp1_neg.Mod(temp1_neg,bn256.Order)
	e4 := new(bn256.GT).ScalarMult(e3,temp1_neg)

	e_mul := new(bn256.GT).Add(e2,e4)

	e5 := bn256.Pair(H,bn256.Gen2)
	temp2_neg := new(big.Int).Neg(temp2)
	temp2_neg.Mod(temp2_neg,bn256.Order)
	e6 := new(bn256.GT).ScalarMult(e5,temp2_neg)

	R3 := new(bn256.GT).Add(e_mul,e6)

	Trx1 := new(bn256.G1).ScalarMult(T1,rx)
	Ur := new(bn256.G1).ScalarMult(U,rDelta1)
	Ur_neg := new(bn256.G1).Neg(Ur)
	R4 := new(bn256.G1).Add(Trx1,Ur_neg)

	Trx2 := new(bn256.G1).ScalarMult(T2,rx)
	Vr := new(bn256.G1).ScalarMult(V,rDelta2)
	Vr_neg := new(bn256.G1).Neg(Vr)
	R5 := new(bn256.G1).Add(Trx2,Vr_neg)

	//计算挑战哈希值c，哈希数据包括
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
	c := HashModOrder(hashData)

	//计算零知识证明s值
	big_mul1 := new(big.Int).Mul(c,alpha)
	sAlpha := new(big.Int).Add(rAlpha,big_mul1)
	sAlpha.Mod(sAlpha,bn256.Order)

	big_mul2 := new(big.Int).Mul(c,beta)
	sBeta := new(big.Int).Add(rBeta,big_mul2)
	sBeta.Mod(sBeta,bn256.Order)

	big_mul3 := new(big.Int).Mul(c,x)
	sx := new(big.Int).Add(rx,big_mul3)
	sx.Mod(sx,bn256.Order)

	big_mul4 := new(big.Int).Mul(c,delta1)
	sDelta1 := new(big.Int).Add(rDelta1,big_mul4)
	sDelta1.Mod(sDelta1,bn256.Order)

	big_mul5 := new(big.Int).Mul(c,delta2)
	sDelta2 := new(big.Int).Add(rDelta2,big_mul5)
	sDelta2.Mod(sDelta2,bn256.Order)

	temp11 := new(big.Int).Add(sAlpha,sBeta)
	temp11.Mod(temp11,bn256.Order)
	temp22 := new(big.Int).Add(sDelta1,sDelta2)
	temp22.Mod(temp22,bn256.Order)

	//输出群签名
	//包含T1,T2,T3,c,sAlpha,sBeta,sx,sDelta1,sDelta2
	//3个G1元素，6个Zp元素

	return &GroupSignature{
		T1,
		T2,
		T3,
		c.Bytes(),
		sAlpha.Bytes(),
		sBeta.Bytes(),
		sx.Bytes(),
		sDelta1.Bytes(),
		sDelta2.Bytes(),
	},nil
}