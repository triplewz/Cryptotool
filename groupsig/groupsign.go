package groupsig

import (
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/pkg/errors"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
)

//所实现群签名方案为BBS群签名方案
// 原文："Short Group Signatures"， https://link.springer.com/content/pdf/10.1007%2F978-3-540-28628-8_3.pdf.

//用户生成群签名
func NewGroupSig(rng *amcl.RAND,gpk *GroupPublicKey,uk *UserKey, message []byte)(*GroupSignature,error){
	if rng == nil || gpk == nil || uk == nil  {
		return nil, errors.Errorf("无法生成群签名：输入为空")
	}

	//签名
	//计算T1,T2,T3
	alpha := RandModOrder(rng)
	beta := RandModOrder(rng)

	U := EcpFromProto(gpk.U)
	V := EcpFromProto(gpk.V)
	H := EcpFromProto(gpk.H)
	W := Ecp2FromProto(gpk.W)
	x := FP256BN.FromBytes(uk.UK1)
	Ax := EcpFromProto(uk.UK2)

	T1 := U.Mul(alpha)
	T2 := V.Mul(beta)
	temp := Modadd(alpha,beta,GroupOrder)
	T3 := H.Mul(temp)
	T3.Add(Ax)

	//计算R1,R2,R3,R4,R5
	delta1 := FP256BN.Modmul(alpha,x,GroupOrder)
	delta2 := FP256BN.Modmul(beta,x,GroupOrder)
	rAlpha := RandModOrder(rng)
	rBeta := RandModOrder(rng)
	rx := RandModOrder(rng)
	rDelta1 := RandModOrder(rng)
	rDelta2 := RandModOrder(rng)
	temp1 := Modadd(rAlpha,rBeta,GroupOrder)
	temp2 := Modadd(rDelta1,rDelta2,GroupOrder)

	R1 := U.Mul(rAlpha)
	R2 := V.Mul(rBeta)

	//R3为GT中元素
	//FP256BN.Ate不支持非固定基双线性对的加法运算，即e(AB,C)≠e(A,C)e(B,C)
	//FP256BN.Ate不支持非固定基双线性对的指数运算，即e(A,B)^r≠e(rA,B)，但满足e(rA,B)=e(A,rB)
	//计算非固定基双线性对的指数运算时，需先计算群元素的指数运算，再计算双线性对，即先计算rA，再计算e(rA,B)
	Wr := W.Mul(temp1)
	e1 := FP256BN.Ate(Wr,H)
	e1.Inverse()
	Hr := H.Mul(temp2)
	e2 := FP256BN.Ate(GenG2,Hr)
	e2.Inverse()
	e1.Mul(e2)
	//计算非固定基双线性对的加法运算时，利用FP256BN.Ate2()代替，即利用Ate2(A,C,B,C)实现e(A,C)e(B,C)
	Gr := GenG2.Mul(rx)
	Ht := H.Mul(temp)
	e3 := FP256BN.Ate2(Gr,Ax,Gr,Ht)
	e3.Mul(e1)
	//使用双线性对时，注意最终计算结果应利用FP256BN.Fexp()处理
	R3 := FP256BN.Fexp(e3)

	R4 := T1.Mul(rx)
	R4.Sub(U.Mul(rDelta1))
	R5 := T2.Mul(rx)
	R5.Sub(V.Mul(rDelta2))

	//计算挑战哈希值c，哈希数据包括
	//7个G1元素，每个长度为2*Fieldbytes+1,1个GT元素，长度为12*Fieldbytes
	//一个消息message
	HashData := make([]byte,7*(2*FieldBytes+1)+12*FieldBytes+len(message))
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
	c := HashModOrder(HashData)

	//计算零知识证明s值
	sAlpha := Modadd(rAlpha,FP256BN.Modmul(c,alpha,GroupOrder),GroupOrder)
	sBeta := Modadd(rBeta,FP256BN.Modmul(c,beta,GroupOrder),GroupOrder)
	sx := Modadd(rx,FP256BN.Modmul(c,x,GroupOrder),GroupOrder)
	sDelta1 := Modadd(rDelta1,FP256BN.Modmul(c,delta1,GroupOrder),GroupOrder)
	sDelta2 := Modadd(rDelta2,FP256BN.Modmul(c,delta2,GroupOrder),GroupOrder)

	//输出群签名
	//包含T1,T2,T3,c,sAlpha,sBeta,sx,sDelta1,sDelta2
	//3个G1元素，6个Zp元素
	return &GroupSignature{
		EcpToProto(T1),
		EcpToProto(T2),
		EcpToProto(T3),
		BigToBytes(c),
		BigToBytes(sAlpha),
		BigToBytes(sBeta),
		BigToBytes(sx),
		BigToBytes(sDelta1),
		BigToBytes(sDelta2),
	},nil
}