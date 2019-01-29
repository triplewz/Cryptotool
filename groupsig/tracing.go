package groupsig

import "github.com/hyperledger/fabric-amcl/amcl/FP256BN"

//群管理者可利用追踪密钥追踪用户身份
func Tracing(GroupSig *GroupSignature, tk *TracingKey) (*K,error) {
	k := new(K)
	//群签名数据转换
	//只需利用T1,T2,T3
	T1 := EcpFromProto(GroupSig.GetT1())
	T2 := EcpFromProto(GroupSig.GetT2())
	T3 := EcpFromProto(GroupSig.GetT3())

	//追踪密钥格式转换
	TK1 := FP256BN.FromBytes(tk.TK1)
	TK2 := FP256BN.FromBytes(tk.TK2)

	//解密恢复用户私钥Ax
	T3.Sub(T1.Mul(TK1))
	T3.Sub(T2.Mul(TK2))
	k.Ax = EcpToProto(T3)

	return k,nil
}
