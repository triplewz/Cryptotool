package groupsig

import (
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
)

//用户注册，群主生成用户签名私钥
func Registration(gmsk *GroupMasterKey,rng *amcl.RAND) (*UserKey,error){
	uk := new(UserKey)

	//生成用户私钥
	x := RandModOrder(rng)
	temp := Modadd(FP256BN.FromBytes(gmsk.Sk),x,GroupOrder)
	temp.Invmodp(GroupOrder)
	Ax := GenG1.Mul(temp)

	uk.UK1 = BigToBytes(x)
	uk.UK2 = EcpToProto(Ax)

	return uk,nil
}