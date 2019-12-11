package bbsgroupsig

import (
	"github.com/cloudflare/bn256"
	"math/big"
)

type K struct {
	Ax     *bn256.G1
}

//群管理者可利用追踪密钥追踪用户身份
func Tracing(groupSig *GroupSignature, tk *TracingKey) (*K,error) {
	k := new(K)
	//群签名数据转换
	//只需利用T1,T2,T3
	T1 := groupSig.T1
	T2 := groupSig.T2
	T3 := groupSig.T3

	//追踪密钥格式转换
	r1 := new(big.Int).SetBytes(tk.TK1)
	r2 := new(big.Int).SetBytes(tk.TK2)

	//解密恢复用户私钥Ax
	Tr1 := new(bn256.G1).ScalarMult(T1,r1)
	Tr1_neg := new(bn256.G1).Neg(Tr1)
	Tr2 := new(bn256.G1).ScalarMult(T2,r2)
	Tr2_neg := new(bn256.G1).Neg(Tr2)

	ret := new(bn256.G1).Add(T3,Tr1_neg)

	k.Ax = new(bn256.G1).Add(ret,Tr2_neg)

	return k,nil
}
