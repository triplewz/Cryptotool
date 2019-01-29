package groupsig

import (
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

//验证群签名
func GroupVerify(GroupSig *GroupSignature,gpk *GroupPublicKey, message []byte) error{
	//转换签名数据格式
	T1 := EcpFromProto(GroupSig.GetT1())
	T2 := EcpFromProto(GroupSig.GetT2())
	T3 := EcpFromProto(GroupSig.GetT3())
	c := FP256BN.FromBytes(GroupSig.GetProofC())
	sAlpha := FP256BN.FromBytes(GroupSig.GetProofSalpha())
	sBeta := FP256BN.FromBytes(GroupSig.GetProofSbeta())
	sx := FP256BN.FromBytes(GroupSig.GetProofSx())
	sDelta1 := FP256BN.FromBytes(GroupSig.GetProofSdelta1())
	sDelta2 := FP256BN.FromBytes(GroupSig.GetProofSdelta2())
	temp1 := Modadd(sAlpha,sBeta,GroupOrder)
	temp2 := Modadd(sDelta1,sDelta2,GroupOrder)

	//转换群公钥格式
	U := EcpFromProto(gpk.U)
	V := EcpFromProto(gpk.V)
	H := EcpFromProto(gpk.H)
	W := Ecp2FromProto(gpk.W)

	//计算R1,R2,R3,R4,R5
	R1 := U.Mul(sAlpha)
	R1.Sub(T1.Mul(c))
	R2 := V.Mul(sBeta)
	R2.Sub(T2.Mul(c))

	Gsx := GenG2.Mul(sx)
	e1 := FP256BN.Ate(Gsx,T3)
	Ht1 := H.Mul(temp1)
	e2 := FP256BN.Ate(W,Ht1)
	e2.Inverse()
	e1.Mul(e2)
	Ht2 := H.Mul(temp2)
	e3 := FP256BN.Ate(GenG2,Ht2)
	e3.Inverse()
	e1.Mul(e3)
	T3c := T3.Mul(c)
	e4 := FP256BN.Ate(W,T3c)
	G1c := GenG1.Mul(c)
	e5 := FP256BN.Ate(GenG2,G1c)
	e5.Inverse()
	e5.Mul(e4)
	e1.Mul(e5)
	R3 := FP256BN.Fexp(e1)

	R4 := T1.Mul(sx)
	R4.Sub(U.Mul(sDelta1))
	R5 := T2.Mul(sx)
	R5.Sub(V.Mul(sDelta2))

	//计算挑战值c'，哈希数据包括
	//7个G1元素，每个长度为2*Fieldbytes+1,1个GT元素，长度为12*Fieldbytes
	//一个消息message
	HashData := make([]byte, 7*(2*FieldBytes+1)+12*FieldBytes+len(message))
	index := 0
	index = appendBytesG1(HashData,index,T1)
	index = appendBytesG1(HashData,index,T2)
	index = appendBytesG1(HashData,index,T3)
	index = appendBytesG1(HashData,index,R1)
	index = appendBytesG1(HashData,index,R2)
	index = appendBytesGT(HashData,index,R3)
	index = appendBytesG1(HashData,index,R4)
	index = appendBytesG1(HashData,index,R5)

	copy(HashData[index:],message)
	cPrime := HashModOrder(HashData)

	//判断c=c'是否相等
	if *c != *cPrime {
		return errors.Errorf("The group signature is invalid!")
	}

	return nil
}